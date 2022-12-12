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
    return c[key]
  catch e
    return default
  finally
    rm(joinpath(c.directory, key), force=true)
  end
  
  return value
end

struct Context
  base::URI
  tokens::Dict{String, Any}
  token_cache::TokenCache
  initial_connection_info::Dict{String, Any}
  
  function Context(base::URI)
    tokens = Dict{String,Any}()
    directory = joinpath("~/.config/tiled/tokens", netloc(base))
    token_cache = TokenCache(directory)
    initial_connection_info = Dict{String, Any}()
    new(base, tokens, token_cache, initial_connection_info)
  end
end

Context(s::String) = Context(URI(s))


function _make_initial_connection(c::Context)
  initial_connection_response = HTTP.get(c.base)
  @assert initial_connection_response.status == 200
  initial_connection_info = JSON.parse(String(initial_connection_response.body))
  return initial_connection_info, initial_connection_response
end


function _ask_for_user_credentials(;username::String=nothing, password::String=nothing)
  # return a Dict("username"=>"", "password"=>"")
  if isnothing(username)
      print("username: ")
      username = readline()
  end
  if isnothing(password)
      password_buffer = Base.getpass("password:")
      password = read(password_buffer, String)
      Base.shred!(password_buffer)
  end

  return Dict{String, String}(
    "username" => username,
    "password" => password
  )
end


function _post_password_auth_credentials(;auth_endpoint, user_credentials)
  password_auth_response = HTTP.post(
    auth_endpoint,
    body=user_credentials,
  )

  return password_auth_response
end


function authenticate!(c::Context; username=nothing, password=nothing)
  initial_connection_info, _ = _make_initial_connection(c)
  empty!(c.initial_connection_info)
  merge!(c.initial_connection_info, initial_connection_info)

  auth_info = c.initial_connection_info["authentication"]  
  providers_info = auth_info["providers"]
  # what if more than one provider?
  provider_info = providers_info[1]
  if provider_info["mode"] == "password"
    password_auth_response = _post_password_auth_credentials(
      auth_endpoint=provider_info["links"]["auth_endpoint"],
      user_credentials=_ask_for_user_credentials(username=username, password=password)
    )
    auth_tokens_info = JSON.parse(String(password_auth_response.body))
    merge!(c.tokens, auth_tokens_info)

    # is this necessary for password mode?
    # refresh_token = replace(refresh_token, "\""=>"")
    #auth_tokens = refresh!(c, auth_tokens_data)

  else
    # don't know what to do!
  end
  
  return auth_tokens_info
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

function _search(c::Context, path="", query=Dict{String,String}(); limit=Inf)
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
        put!(ch, x)
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

function visit(f, c::TiledClient.Context, path="", query=Dict{String,String}(); limit=Inf)
  data = _search(c, path, query; limit)
  results = Channel(Inf)
  @sync for x in data
    @async put!(results, f(x))
  end
  close(results)
  return collect(results)
end
