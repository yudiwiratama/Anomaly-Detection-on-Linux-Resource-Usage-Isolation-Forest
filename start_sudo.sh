#!/bin/bash
# Script untuk menjalankan Conntrack Dashboard dengan sudo (untuk akses conntrack)

echo "Starting Conntrack Dashboard dengan sudo..."
echo "Installing dependencies if needed..."

# Deteksi Python dari venv jika ada
if [ -n "$VIRTUAL_ENV" ]; then
    PYTHON_CMD="$VIRTUAL_ENV/bin/python3"
    PIP_CMD="$VIRTUAL_ENV/bin/pip"
    echo "✓ Menggunakan Python dari venv: $VIRTUAL_ENV"
    # Install dependencies di venv
    $PIP_CMD install -q -r requirements.txt
else
    # Coba cari venv di direktori saat ini
    if [ -f "venv/bin/python3" ]; then
        PYTHON_CMD="$(pwd)/venv/bin/python3"
        PIP_CMD="$(pwd)/venv/bin/pip"
        echo "✓ Menggunakan Python dari venv lokal: $(pwd)/venv"
        $PIP_CMD install -q -r requirements.txt
    else
        PYTHON_CMD="python3"
        PIP_CMD="pip3"
        echo " Tidak ada venv aktif, menggunakan system Python"
        echo " Install dependencies dengan sudo..."
        sudo $PIP_CMD install -q -r requirements.txt
    fi
fi

echo " Starting server on http://localhost:8000"
echo "Server berjalan dengan sudo untuk akses conntrack"
echo "Press Ctrl+C to stop"
echo ""

# Gunakan Python dari venv dengan sudo (gunakan absolute path)
if [[ "$PYTHON_CMD" == /* ]]; then
    # Sudah absolute path
    sudo "$PYTHON_CMD" app.py
else
    # Relative path, convert ke absolute
    sudo "$(realpath "$PYTHON_CMD" 2>/dev/null || which "$PYTHON_CMD")" app.py
fi

