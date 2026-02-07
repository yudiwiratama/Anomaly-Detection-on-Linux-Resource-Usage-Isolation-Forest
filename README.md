# Anomaly-Detection-on-Linux-Resource-Usage-Isolation-Forest
## Fitur

- **Visualisasi Real-time**: Grafik interaktif untuk protocol, state, IP addresses, dan ports
- **Agregasi & Grouping**: Data dikelompokkan berdasarkan berbagai kriteria dengan count dan bytes tracking
- **Multiple Charts**: 
  - Distribusi Protocol (Doughnut Chart)
  - Distribusi State (Bar Chart)
  - Top 10 Source IP
  - Top 10 Destination IP
  - Top 10 Destination Ports
  - Protocol vs State Matrix (Stacked Bar Chart)
- **Time Series Analytics**: Historical data tracking dengan time series charts
- **Grouping Statistics**: Detailed grouping dengan count dan bytes untuk semua metrics (bukan hanya top 10)
- **Pencarian & Filter**: Filter koneksi berdasarkan protocol, state, IP, atau port
- **Sorting & Limit**: Sort tabel dan limit jumlah data yang ditampilkan
- **Auto-refresh**: Update otomatis setiap 5 detik
- **Database**: SQLite database untuk menyimpan historical data
- **Responsive Design**: Tampilan yang optimal di desktop dan mobile


## Prasyarat

- Python 3.7+
- Akses ke `/proc/net/nf_conntrack` atau command `conntrack`
- Akses root atau user dengan permission membaca conntrack data


## Instalasi

1. Install dependencies:
```bash
pip install -r requirements.txt
```

2. Pastikan memiliki akses ke conntrack data:
```bash
# Cek apakah conntrack command tersedia
conntrack -L

# Atau cek file /proc/net/nf_conntrack
cat /proc/net/nf_conntrack | head
```

3. Running dashboard

#### Quick running (Opsi 1)

```bash
# Build dan jalankan
docker-compose up -d

# Lihat logs
docker-compose logs -f

# Stop
docker-compose down
```


#### With Venv (Opsi 2)
**Jika menggunakan virtual environment:**
```bash
# Aktifkan venv terlebih dahulu
source venv/bin/activate  # atau nama venv Anda

# Kemudian jalankan script
chmod +x start_sudo.sh
./start_sudo.sh
```

#### Buka browser dan akses:
```
http://localhost:8000
```
