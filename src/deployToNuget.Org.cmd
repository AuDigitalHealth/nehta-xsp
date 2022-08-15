del *.nupkg

REM Use dotnet for packaing now
REM NuGet.exe pack Nehta.Xsp\Nehta.Xsp.csproj -Properties Configuration=Release
dotnet pack .\Nehta.Xsp\Nehta.Xsp.csproj -c Release -o .

forfiles /m *.nupkg /c "cmd /c NuGet.exe push @FILE -Source https://www.nuget.org/api/v2/package"
