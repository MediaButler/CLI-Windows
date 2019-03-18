FROM microsoft/powershell:latest
LABEL maintainer="MediaButler"
COPY ./ /app/
CMD ["pwsh", "/app/mediabutler.ps1"]