module TiledClient

using URIs
using HTTP
using JSON

export authenticate!, refresh!, reauthenticate!, logout!, visit

include("client.jl")

end # module
