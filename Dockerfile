FROM mcr.microsoft.com/dotnet/core/sdk:3.1.101 AS build-env
WORKDIR /app

COPY ./. ./

RUN dotnet restore Bizanc.io.Matching.sln 
RUN mkdir out
RUN dotnet publish Bizanc.io.Matching.App/Bizanc.io.Matching.App.csproj -c Release -o ./out

# build runtime image
FROM mcr.microsoft.com/dotnet/core/aspnet:3.1.1
WORKDIR /app
COPY --from=build-env app/out ./

ENTRYPOINT ["dotnet", "Bizanc.io.Matching.App.dll"]