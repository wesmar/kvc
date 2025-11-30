#!/bin/bash

# Konfiguracja
REPO_DIR="/c/Projekty/github/kvc"
TAG="v1.0.1"
REPO="wesmar/kvc"

cd "$REPO_DIR" || exit 1

echo "======================================"
echo "🔧 KROK 1: Pakowanie plików"
echo "======================================"
./pack-data.sh
if [ $? -ne 0 ]; then
    echo "❌ Błąd pakowania!"
    exit 1
fi

echo ""
echo "======================================"
echo "🗑️  KROK 2: Usuwanie starych assetów"
echo "======================================"

# Usuń tylko kvc.7z i kvc.enc (zostaw 'run')
gh release delete-asset "$TAG" kvc.7z --yes 2>/dev/null && echo "✅ Usunięto kvc.7z" || echo "⚠️  kvc.7z nie istniało"
gh release delete-asset "$TAG" kvc.enc --yes 2>/dev/null && echo "✅ Usunięto kvc.enc" || echo "⚠️  kvc.enc nie istniało"

echo ""
echo "======================================"
echo "📤 KROK 3: Upload nowych plików"
echo "======================================"

gh release upload "$TAG" \
    "data/kvc.7z#kvc.7z" \
    "data/kvc.enc#kvc.enc" \
    --clobber

if [ $? -eq 0 ]; then
    echo ""
    echo "======================================"
    echo "✅ SUKCES!"
    echo "======================================"
    echo "Release zaktualizowany: https://github.com/$REPO/releases/tag/$TAG"
else
    echo "❌ Błąd uploadu!"
    exit 1
fi