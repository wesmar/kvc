#!/bin/bash

cd "/c/Projekty/github/kvc/data" || exit 1
ARCHIVE="kvc.7z"
PASSWORD="github.com"

# Usuń stare archiwum
rm -f "$ARCHIVE"

echo "📦 Pakuję data/ do $ARCHIVE"
echo "🔒 Hasło: $PASSWORD"

# Pakuj wszystko OPRÓCZ pliku kvc.7z
"/c/Program Files/7-Zip/7z.exe" a -t7z -mx=9 -p"$PASSWORD" "$ARCHIVE" \
    -x!"$ARCHIVE" .

if [ $? -eq 0 ]; then
    echo "✅ Success! $(du -h "$ARCHIVE" | cut -f1)"
else
    echo "❌ Błąd!"
fi