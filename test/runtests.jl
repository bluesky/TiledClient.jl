using Test

using TiledClient


@testset "Test Password Authentication" begin
 
    tiled_context = TiledClient.Context("http://127.0.0.1:8000/api/")
    @test length(tiled_context.tokens) == 0

    TiledClient.authenticate!(tiled_context, username="alice", password="secret1")
    @test length(tiled_context.tokens) == 5
    @test length(tiled_context.tokens["refresh_token"]) > 0
    @test length(tiled_context.tokens["access_token"]) > 0
    @test tiled_context.tokens["token_type"] == "bearer"

end
