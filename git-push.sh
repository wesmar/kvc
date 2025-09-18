#!/bin/bash

# Konfiguracja
REPO_DIR="/c/Projekty/github/kvc"
BRANCH="main"

# Funkcja do wypychania zmian
push_changes() {
    echo "Przechodzę do katalogu: $REPO_DIR"
    cd "$REPO_DIR" || { echo "Błąd: Nie można przejść do katalogu!"; exit 1; }
    
    # Sprawdź czy są zmiany
    echo "Sprawdzam zmiany..."
    if git diff --quiet && git diff --staged --quiet; then
        echo "✅ Brak zmian do commitowania."
        return 0
    fi

    # Pokaż zmiany
    echo "Zmiany do commitowania:"
    git status --short
    
    # Dodaj wszystkie zmiany
    echo "Dodaję zmiany..."
    git add .
    
    # Commit z wiadomością
    if [ -n "$1" ]; then
        git commit -m "$1"
    else
        git commit -m "Aktualizacja: $(date '+%Y-%m-%d %H:%M:%S')"
    fi
    
    # Push
    echo "Wypycham zmiany na GitHub..."
    git push origin "$BRANCH"
    
    echo "✅ Zmiany wypchnięte pomyślnie!"
    echo "✅ Branch: $BRANCH"
}

# Obsługa parametrów
if [ "$#" -gt 1 ]; then
    echo "Użycie: $0 [wiadomość_commit]"
    exit 1
fi

# Uruchom funkcję
push_changes "$1"