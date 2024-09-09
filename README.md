# fdpi
fuck dpi, http proxy:
- effective fuck dpi
- caching (1000 entries) DNS resolver enabled: DoH Cloudflare
- log support

## install
```
git clone https://github.com/Cergoo/fdpi.git
cargo build --release

or

download release bin file 
```

## run
for: 
- youtube.com 
- rutracker.org
- index.minfin.com.ua/russian-invading/casualties
- linkedin.com
- medium.com
- meduza.io
- and other
```
./fdpi -b2 -s2 -s4 -s2 -t4
google-chrome --proxy-server="http://127.0.0.1:8080"
```

### ok, new release 0.2.0.


<img src="img1.jpg" width="500">