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
## Install package and library
pip install -r requirements.txt

## install conntrack utils
apt install conntrack -y

## enable conntrack if disabled by default linux
iptables -A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT

## how to enable bytes for conntrack if wanna see
sysctl -w net.netfilter.nf_conntrack_acct=1

## enable persistent bytes display in conntrak
echo "net.netfilter.nf_conntrack_acct = 1" >> /etc/sysctl.conf
sysctl -p

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


<details>
<summary>Preview Dashboard 
</summary>

<img width="947" height="927" alt="Screenshot_08-Feb_01-40-14_1229" src="https://github.com/user-attachments/assets/2c749059-6a54-49bb-84b5-89998cfe4293" />

<img width="954" height="920" alt="Screenshot_08-Feb_01-40-23_215" src="https://github.com/user-attachments/assets/3673710a-4233-4c9b-a9c0-750987ee85ba" />

<img width="945" height="443" alt="Screenshot_08-Feb_01-40-42_23413" src="https://github.com/user-attachments/assets/0ebedf6a-0109-490c-9d15-ce218cadb57f" />

<img width="958" height="663" alt="Screenshot_08-Feb_01-40-58_21141" src="https://github.com/user-attachments/assets/522d8cd1-d7b7-41cb-868b-4c81dccd889d" />

<img width="949" height="450" alt="Screenshot_08-Feb_01-41-06_2462" src="https://github.com/user-attachments/assets/2c6e72ea-9ac1-4557-a409-51b9640372bf" />



</details>

