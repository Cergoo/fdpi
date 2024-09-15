# fdpi
fuck dpi, http proxy:
- (-b) split body
- (-s) split sni
- (-e) edit sni  
- caching (1000 entries) DNS resolver enabled: DoH Cloudflare
- log support

## install
```
git clone https://github.com/Cergoo/fdpi.git
cargo build --release
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
./fdpi -b2 -s2 -s4 -s2 -t4 (-e can try it)
google-chrome --proxy-server="http://127.0.0.1:8080"
```
or
```
./fdpi -b2 -s2 -s4 -s2 -t4 -e
```
### ok, new release 0.2.1.
