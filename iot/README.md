# `iot/` — experimental hardware status bridge

> **Status: experimental. Not wired into the CLI.**
> No CYPHEX command starts or requires any of this, and nothing here is
> installed by `pip install -e .`. Do not describe it as a shipped feature.

A physical status display for a running scan: a Raspberry Pi Pico (MicroPython)
drives LEDs, an SSD1306 OLED and a buzzer, and a laptop-side bridge feeds it
live scan state over USB serial.

| File | Runs on | Does |
|---|---|---|
| `wokwi_main.py` | Pi Pico (MicroPython) | Reads the serial protocol; drives `Pin` / `PWM` / `ssd1306` |
| `iot_serial_bridge.py` | your laptop | Connects to the Pico and forwards CYPHEX scan status |
| `wokwi_diagram.json` | [Wokwi](https://wokwi.com) | Circuit definition — simulate it without hardware |

## Use

```bash
python iot/iot_serial_bridge.py --port /dev/tty.usbmodem1101   # macOS/Linux
python iot/iot_serial_bridge.py --port COM3                    # Windows
```

Then start a scan; the device reacts live.

Wire protocol, sent line-by-line over serial:

```
STATUS:scanning:Agent 01 Recon:Checking headers
```

`wokwi_main.py` targets MicroPython on the Pico and needs `ssd1306.py` on the
device. It will not run under desktop CPython — `machine` is not available
there.

## Caveats

- Serial port names are platform-specific and are not auto-detected.
- The bridge follows scan status only. It has no bearing on findings, patches,
  or the Verify Gate, and cannot influence a scan's outcome.
