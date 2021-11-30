using URIs
using HTTP
using JSON

function netloc(uri::URI)
  @assert !isempty(uri.host)
  
  out = "$(uri.host)"
  if !isempty(uri.port)
    out = "$out:$(uri.port)"
  end
  
  if !isempty(uri.userinfo)
    out = "$(uri.userinfo)@$out"
  end
  
  return out 
end

struct TokenCache
  directory::String
  
  function TokenCache(directory::String)
    directory = abspath(expanduser(directory))
    mkpath(directory)
    new(directory)
  end
end

function Base.getindex(c::TokenCache, key::String)
  file = joinpath(c.directory, key)
  @assert isfile(file)
  value = open(file, "r") do f
    read(f, String)
  end
  return value
end

function Base.setindex!(c::TokenCache, value::String, key::String)
  file = joinpath(c.directory, key)
  touch(file)
  chmod(file, 0o600)
  open(file, "w") do f
    write(f, value)
  end
  return value
end

function Base.pop!(c::TokenCache, key::String, default=nothing)
  try
    value = c[key]
  catch e
    value = default
  finally
    rm(joinpath(c.directory, key), force=true)
  end
  
  return value
end

struct Context
  base::URI
  tokens::Dict{String, String}
  token_cache::TokenCache
  
  function Context(base::URI)
    tokens = Dict{String,String}()
    directory = joinpath("~/.config/tiled/tokens", netloc(base))
    token_cache = TokenCache(directory)
    new(base, tokens, token_cache)
  end
end

Context(s::String) = Context(URI(s))

function authenticate!(c::Context)
  r = HTTP.get(c.base)
  @assert r.status == 200
  data = JSON.parse(String(r.body))
  auth = data["authentication"]
  @assert auth["type"] == "external"
  
  endpoint = auth["endpoint"]
  
  println("visit: $endpoint")
  
  buffer = Base.getpass("access code:")
  refresh_token = read(buffer, String)
  Base.shred!(buffer)
  refresh_token = replace(refresh_token, "\""=>"")
  
  tokens = refresh!(c, refresh_token)
  
  return tokens
end

function refresh!(c::Context, refresh_token=nothing)
  if isnothing(refresh_token)
    refresh_token = c.token_cache["refresh_token"]
  end
  
  url = URI(c.base, path="/auth/token/refresh")
  headers = ["Content-Type" => "application/json"]
  data = Dict("refresh_token" => refresh_token)
  
  r = HTTP.post(url, headers, JSON.json(data))
  @assert r.status == 200
  
  auth = JSON.parse(String(r.body))
  access_token = auth["access_token"]
  refresh_token = auth["refresh_token"]
  
  c.token_cache["refresh_token"] = refresh_token
  
  c.tokens["refresh_token"] = refresh_token
  c.tokens["access_token"] = access_token
  
  return Dict("refresh_token" => refresh_token, "access_token" => access_token)
end

function reauthenticate!(c::Context)
  try
    refresh!(c)
  catch e
    authenticate!(c)
  end
end

function logout!(c::Context)
  pop!(c.token_cache, "refresh_token", nothing)
  pop!(c.tokens, "refresh_token", nothing)
  pop!(c.tokens, "access_token", nothing)
  return nothing
end

function HTTP.get(c::Context, path, query=Dict{String,String}(), headers=Dict{String,String}(); kwargs...)
  url = URI(c.base; path, query)
  access_token = c.tokens["access_token"]
  headers["Authorization"] = "Bearer $access_token"
  return HTTP.get(url, headers, kwargs...)
end

function search(f, c::Context, path="", query=Dict{String,String}(); limit=Inf)
  path = "/search/" * path
  
  Channel(Inf, spawn=true) do ch
    
    n = 0
    while true
      r = HTTP.get(c, path, query)
      @assert r.status == 200
      page_data = JSON.parse(String(r.body))
      
      @assert "data" in keys(page_data)
      @assert "links" in keys(page_data)
      
      for x in page_data["data"]
        put!(ch, f(x))
        n += 1
        n == limit && break
      end
      
      next_page = page_data["links"]["next"]
      
      isnothing(next_page) && break
      n == limit && break
      
      merge!(query, queryparams(URI(next_page)))
    end
    close(ch)
  end
end
