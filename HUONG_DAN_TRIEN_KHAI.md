# LAN Canary (bản đã vá) — Hướng dẫn triển khai trên Home Assistant

Bản này dựa trên `robainbinder/ha-lan-canary-tarpit` 1.0.0 (giấy phép MIT), đã sửa các lỗi trong bản đánh giá.

## Đã sửa những gì

| Lỗi ở bản gốc | Cách sửa |
|---|---|
| Lần dò thứ 2 tắt rồi bật lại `canary_intrusion_alert`, kích hoạt automation reset và **thả hết socket đang giữ** | Hit chỉ **bật** báo động, không bao giờ tắt. Push đi qua event `lan_canary_hit`. Hàm reset gọi lặp lại cũng không gây hại |
| Webhook `local_only: false`, cho phép GET, ID công khai | `local_only: true`, chỉ POST, ID lấy từ `secrets.yaml`, tối đa 1 push mỗi 30 giây |
| Mỗi kết nối đều tạo push + tra DNS + 4 lệnh gọi service, nên bị spam khi có người quét | Mỗi IP chỉ báo 1 lần trong 5 phút, toàn hệ thống tối đa 6 lần mỗi phút. Các lần bị bỏ qua vẫn được cộng vào bộ đếm (`+N suppressed`) |
| Giới hạn 64 socket không chặn được quá tải | Kiểm tra giới hạn trước. Vượt giới hạn thì đóng kết nối ngay |
| Tra DNS ngược không có timeout | Timeout 2 giây, cache 1 giờ, lọc ký tự trong hostname (thiết bị tấn công có thể tự đặt hostname qua DHCP) |
| Ai gửi chuỗi `CANARY_HEALTHCHECK` cũng né được báo động | Chỉ bỏ qua khi khớp token bí mật bạn tự đặt (không bắt buộc) |
| Chiếm cổng 3306 (trùng add-on MariaDB) | Mặc định không mở 3306. Có thể chọn cổng trong cấu hình |
| Chỉ nghe IPv4 | Nghe cả IPv4 và IPv6. Tự lùi về IPv4 nếu IPv6 lỗi |
| Không đóng server khi HA tắt | Đóng listener và socket khi HA dừng |
| Bộ đếm và log bị reset mỗi lần khởi động lại | Dùng `counter` với `restore: true`, bỏ `initial` |
| State của template sensor có thể vượt 255 ký tự | State ngắn gọn, chi tiết nằm ở attribute `last_event` |

Đã kiểm thử logic bằng HA giả lập (stub) trên Python 3.13: 22/22 test đạt, gồm kiểm tra rằng lần dò thứ 2 không còn thả socket. **Chưa chạy trên một HA thật**, nên hãy làm kỹ bước 8 và 9 bên dưới.

## Cấu trúc thư mục

```
ha-lan-canary-fixed/
├── custom_components/lan_canary/
│   ├── __init__.py
│   ├── manifest.json
│   └── services.yaml
├── packages/lan_canary_tarpit.yaml
└── LICENSE
```

---

## Bước 0 — Kiểm tra kiểu cài đặt HA

Vào **Cài đặt → Hệ thống → Thông tin** (Settings → System → About) và xem *Installation type*:

- **Home Assistant OS / Supervised:** dùng được ngay.
- **Container (Docker):** container phải chạy với `network_mode: host`. Nếu không, các cổng không mở ra LAN và IP nguồn có thể bị sai.
- **Core (venv):** dùng được.

> Đừng bao giờ mở port (port-forward) các cổng 2121/2222/2323/5900/8088 từ router ra Internet. Công cụ này chỉ dùng để canh mạng **nội bộ**.

## Bước 1 — Kiểm tra trùng cổng

Từ máy Windows, thay `192.168.1.50` bằng IP của HA rồi chạy:

```powershell
2121,2222,2323,5900,8088 | ForEach-Object { "{0}: {1}" -f $_, (Test-NetConnection 192.168.1.50 -Port $_ -WarningAction SilentlyContinue).TcpTestSucceeded }
```

Trước khi cài, tất cả phải là `False`. Cổng nào ra `True` tức là đã có dịch vụ khác dùng (ví dụ add-on SSH ở 2222). Hãy bỏ cổng đó khỏi `ports:` ở bước 5.

## Bước 2 — Tìm tên dịch vụ notify của điện thoại

Điện thoại cần cài app Home Assistant Companion và đã đăng nhập.
Vào **Công cụ nhà phát triển → Hành động** (Developer tools → Actions) và gõ `notify.mobile_app`. Bạn sẽ thấy tên kiểu `notify.mobile_app_pixel_8`. Chép lại tên này.

## Bước 3 — Chép file lên HA

Chọn một trong các cách:

- **Add-on Samba share** (dễ nhất trên Windows): cài và khởi động add-on, rồi mở `\\homeassistant.local\config` (hoặc `\\<IP-HA>\config`) trong File Explorer.
- **Add-on Studio Code Server** hoặc **File editor:** tạo thư mục và file rồi dán nội dung vào.

Kết quả cần có trên HA:

```
/config/custom_components/lan_canary/__init__.py
/config/custom_components/lan_canary/manifest.json
/config/custom_components/lan_canary/services.yaml
/config/packages/lan_canary_tarpit.yaml
```

(Tạo thư mục `custom_components` và `packages` nếu chưa có.)

## Bước 4 — Thêm webhook ID bí mật vào `secrets.yaml`

Tạo một chuỗi ngẫu nhiên trên Windows:

```powershell
-join ((48..57)+(97..122) | Get-Random -Count 32 | ForEach-Object {[char]$_})
```

Thêm vào `/config/secrets.yaml`:

```yaml
lan_canary_webhook_id: "dan_chuoi_ngau_nhien_vao_day"
```

> Nếu không dùng OpenCanary, bạn vẫn có thể giữ dòng này (vô hại). Nếu muốn bỏ, hãy **xóa cả automation số 2** trong file package, không thì HA báo lỗi thiếu secret.

## Bước 5 — Sửa `configuration.yaml`

Thêm vào `/config/configuration.yaml`:

```yaml
homeassistant:
  packages: !include_dir_named packages

lan_canary:
  ports: [2121, 2222, 2323, 5900, 8088]   # thêm 3306 nếu KHÔNG dùng MariaDB add-on
  ignore_ips:
    - 192.168.1.20        # thiết bị được phép quét (Uptime Kuma, NAS, máy admin...)
  # per_ip_cooldown: 300        # số giây giữa 2 lần báo cho cùng 1 IP
  # max_alerts_per_minute: 6    # giới hạn push cho toàn hệ thống
  # max_tarpits: 64             # số socket giữ cùng lúc
  # healthcheck_token: !secret lan_canary_health_token   # >= 16 ký tự, không bắt buộc
  # bind_host: 192.168.1.50     # chỉ nghe trên 1 IP; bỏ trống = mọi giao diện
```

**Lưu ý:** nếu file đã có khối `homeassistant:`, chỉ thêm dòng `packages:` vào khối đó. Đừng tạo khối thứ hai.

## Bước 6 — Sửa dịch vụ notify trong package

Mở `/config/packages/lan_canary_tarpit.yaml` và tìm dòng có `>>> CHANGE ME <<<`:

```yaml
      - action: notify.mobile_app_CHANGE_ME
```

Thay bằng tên bạn đã tìm ở bước 2. Chỉ cần sửa ở **một chỗ** này, vì mọi automation đều gửi qua `script.lan_canary_notify`.

## Bước 7 — Kiểm tra cấu hình rồi khởi động lại

1. Vào **Công cụ nhà phát triển → YAML → Kiểm tra cấu hình** (Check configuration). Phải ra "Configuration valid".
2. Vào **Cài đặt → Hệ thống → nút nguồn (góc trên bên phải) → Khởi động lại Home Assistant**. Custom component mới cần khởi động lại hẳn, không chỉ reload YAML.

## Bước 8 — Xác nhận đã chạy

- **Cài đặt → Hệ thống → Nhật ký** (Logs): tìm `lan_canary`. Phải có dòng `LAN Canary listening on port 2222 (SSH) ...` cho từng cổng. Nếu thấy `cannot bind port` thì cổng đó đang bị trùng (quay lại bước 1).
- **Công cụ nhà phát triển → Trạng thái:** phải có các entity `counter.canary_hit_count`, `input_text.canary_last_event`, `input_boolean.canary_intrusion_alert`, `sensor.canary_tripwire_status`, `script.lan_canary_notify`.
- Chạy lại lệnh ở bước 1: các cổng đã cài phải chuyển sang `True`.

## Bước 9 — Thử báo động

Từ máy Windows (không nằm trong `ignore_ips`):

```powershell
Test-NetConnection 192.168.1.50 -Port 2222
```

Kết quả mong đợi, sau khoảng 2 giây:
- Điện thoại nhận push "LAN CANARY TRIPPED", có IP và hostname máy bạn.
- `input_boolean.canary_intrusion_alert` chuyển sang `on` và bộ đếm tăng 1.

Muốn xem tarpit hoạt động, dùng `ncat 192.168.1.50 2222` (cài Nmap) hoặc `telnet`. Cứ 10 giây bạn sẽ thấy một dòng `Synology-DSM-KeyCheck-N: wait`.

**Tắt báo động:** bấm nút "Acknowledge & release tarpit" trên thông báo, hoặc tắt `canary_intrusion_alert`. Mọi socket được thả và báo động trở lại trạng thái canh gác.

> Thử lại ngay từ cùng một máy sẽ **không** có push mới trong 5 phút (cố ý chống spam). Lần đó chỉ được ghi vào bộ đếm dạng `+N suppressed`.

## Bước 10 (không bắt buộc) — Thẻ dashboard

Thêm thẻ **Manual** với nội dung:

```yaml
type: entities
title: LAN Canary
entities:
  - entity: sensor.canary_tripwire_status
  - entity: input_text.canary_last_event
  - entity: counter.canary_hit_count
  - entity: input_boolean.canary_intrusion_alert
    name: Báo động (tắt để reset)
```

## Báo động nhầm thường gặp

Những thứ sau cũng "quét" mạng và sẽ kích hoạt canary. Hãy thêm IP của chúng vào `ignore_ips`:
- App **Fing** hoặc các app quét mạng trên điện thoại
- Uptime Kuma, Nmap, Angry IP Scanner chạy theo lịch
- Một số router hoặc NAS có tính năng "quét thiết bị" hay "bảo mật mạng"

Ngoài các trường hợp trên, báo động thật sự đáng chú ý: một thiết bị trong nhà đang dò các cổng NAS.

## Tích hợp OpenCanary (không bắt buộc)

Cấu hình webhook của OpenCanary gửi **POST** tới:

```
http://<IP-HA>:8123/api/webhook/<lan_canary_webhook_id trong secrets.yaml>
```

Body JSON có các trường `src_host`, `dst_port`, `logtype`. Webhook chỉ nhận yêu cầu từ trong LAN.

## Gỡ cài đặt

1. Xóa `lan_canary:` khỏi `configuration.yaml`.
2. Xóa `/config/packages/lan_canary_tarpit.yaml` và thư mục `/config/custom_components/lan_canary/`.
3. Khởi động lại HA.
