#!/usr/bin/env python3
"""
Dynamic Flow Diagram Generator for TSS (Timestamping Service) Project.
Generates publication-quality colorful SVG, PNG sequence diagrams with harmonious, modern palettes.
"""

import os
from PIL import Image, ImageDraw, ImageFont

OUTPUT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "figures"))
os.makedirs(OUTPUT_DIR, exist_ok=True)

# ----------------------------------------------------------------------
# Modern Cohesive Color System (Tailwind / Modern Tech Doc Palette)
# ----------------------------------------------------------------------
BG_COLOR = "#ffffff"
LIFELINE_COLOR = "#cbd5e1"  # Slate-300

# Theme per Participant Type
THEMES = {
    "client": {
        "header_bg": "#eff6ff",     # Blue-50
        "header_border": "#93c5fd", # Blue-300
        "header_text": "#1e40af",   # Blue-800
        "note_bg": "#2563eb",       # Blue-600
        "note_border": "#1d4ed8",   # Blue-700
        "note_text": "#ffffff",
    },
    "server": {
        "header_bg": "#f5f3ff",     # Purple-50
        "header_border": "#c4b5fd", # Purple-300
        "header_text": "#5b21b6",   # Purple-800
        "note_bg": "#4f46e5",       # Indigo-600
        "note_border": "#4338ca",   # Indigo-700
        "note_text": "#ffffff",
    },
    "auditor": {
        "header_bg": "#f0fdf4",     # Green-50
        "header_border": "#86efac", # Green-300
        "header_text": "#166534",   # Green-800
        "note_bg": "#059669",       # Emerald-600
        "note_border": "#047857",   # Emerald-700
        "note_text": "#ffffff",
    },
    "tool": {
        "header_bg": "#f8fafc",     # Slate-50
        "header_border": "#94a3b8", # Slate-400
        "header_text": "#0f172a",   # Slate-900
        "note_bg": "#334155",       # Slate-700
        "note_border": "#1e293b",   # Slate-800
        "note_text": "#ffffff",
    },
    "neutral": {
        "header_bg": "#f8fafc",
        "header_border": "#cbd5e1",
        "header_text": "#1e293b",
        "note_bg": "#475569",       # Slate-600
        "note_border": "#334155",
        "note_text": "#ffffff",
    }
}

# Message Payloads
PAYLOAD_BG = "#1e293b"      # Slate-800
PAYLOAD_BORDER = "#0f172a"  # Slate-900
PAYLOAD_TEXT = "#f8fafc"

# Banner Styles
SPANS = {
    "info": {
        "bg": "#1e293b",    # Slate-800 (Clean navy dark)
        "text": "#ffffff"
    },
    "success": {
        "bg": "#065f46",    # Emerald-800 (Rich green)
        "text": "#ecfdf5"
    },
    "warning": {
        "bg": "#9a3412",    # Amber/Orange-800
        "text": "#fffbeb"
    },
    "error": {
        "bg": "#991b1b",    # Red-800
        "text": "#fef2f2"
    }
}

ARROW_COLOR = "#1e293b"
ARROW_TEXT = "#0f172a"
CIRCLE_BG = "#1e293b"
CIRCLE_TEXT = "#ffffff"

FONT_REGULAR_PATH = "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf"
FONT_BOLD_PATH = "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf"


class FlowDiagram:
    def __init__(self, width=660, participants=None, p_themes=None, box_w=170):
        self.width = width
        self.participants = participants or ["Client", "Server"]
        self.p_themes = p_themes or ["client", "server"]
        self.box_w = box_w
        self.items = []
        self.p_coords = []
        
        margin = 155
        n = len(self.participants)
        if n == 1:
            self.p_coords = [width // 2]
        else:
            step = (width - 2 * margin) / (n - 1)
            self.p_coords = [int(margin + i * step) for i in range(n)]

    def add_span(self, text, style="info", height=34):
        self.items.append({"type": "span", "text": text, "style": style, "height": height})

    def add_note(self, p_idx, lines, width=220, custom_theme=None):
        theme_key = custom_theme or self.p_themes[p_idx]
        self.items.append({
            "type": "note",
            "p_idx": p_idx,
            "theme": theme_key,
            "lines": lines if isinstance(lines, list) else [lines],
            "width": width
        })

    def add_message(self, from_p, to_p, label, payload_lines=None, step_num=None, payload_width=250):
        self.items.append({
            "type": "message",
            "from_p": from_p,
            "to_p": to_p,
            "label": label,
            "payload_lines": payload_lines if isinstance(payload_lines, list) else ([payload_lines] if payload_lines else None),
            "step_num": step_num,
            "payload_width": payload_width
        })

    def _compute_layout(self):
        top_margin = 25
        header_h = 42
        curr_y = top_margin + header_h + 18
        layout_elements = []
        
        for item in self.items:
            itype = item["type"]
            
            if itype == "span":
                sh = item["height"]
                layout_elements.append({
                    "type": "span",
                    "y": curr_y,
                    "height": sh,
                    "text": item["text"],
                    "style": item["style"]
                })
                curr_y += sh + 16

            elif itype == "note":
                lines = item["lines"]
                line_h = 16
                pad_v = 8
                nh = pad_v * 2 + len(lines) * line_h
                layout_elements.append({
                    "type": "note",
                    "p_idx": item["p_idx"],
                    "theme": item["theme"],
                    "y": curr_y,
                    "height": nh,
                    "width": item["width"],
                    "lines": lines,
                    "line_h": line_h,
                    "pad_v": pad_v
                })
                curr_y += nh + 14

            elif itype == "message":
                label = item["label"]
                payload_lines = item.get("payload_lines")
                arrow_y = curr_y + 18
                
                payload_info = None
                if payload_lines:
                    line_h = 15
                    pad_v = 7
                    ph = pad_v * 2 + len(payload_lines) * line_h
                    payload_y = arrow_y + 8
                    payload_info = {
                        "y": payload_y,
                        "height": ph,
                        "width": item["payload_width"],
                        "lines": payload_lines,
                        "line_h": line_h,
                        "pad_v": pad_v
                    }
                    total_elem_h = (payload_y + ph) - curr_y
                else:
                    total_elem_h = 24
                
                layout_elements.append({
                    "type": "message",
                    "from_p": item["from_p"],
                    "to_p": item["to_p"],
                    "label": label,
                    "step_num": item["step_num"],
                    "arrow_y": arrow_y,
                    "payload": payload_info
                })
                curr_y += total_elem_h + 16

        total_height = curr_y + header_h + top_margin
        return layout_elements, total_height, top_margin, header_h

    def render_png(self, filename, scale=2):
        layout_elements, total_height, top_margin, header_h = self._compute_layout()
        
        W = int(self.width * scale)
        H = int(total_height * scale)
        
        img = Image.new("RGBA", (W, H), BG_COLOR)
        draw = ImageDraw.Draw(img)

        # Scaled Fonts
        f_part = ImageFont.truetype(FONT_BOLD_PATH, int(13.5 * scale))
        f_span = ImageFont.truetype(FONT_BOLD_PATH, int(11 * scale))
        f_note = ImageFont.truetype(FONT_REGULAR_PATH, int(11 * scale))
        f_note_bold = ImageFont.truetype(FONT_BOLD_PATH, int(11 * scale))
        f_arrow = ImageFont.truetype(FONT_REGULAR_PATH, int(12 * scale))
        f_num = ImageFont.truetype(FONT_BOLD_PATH, int(10.5 * scale))

        top_box_y = int(top_margin * scale)
        bot_box_y = int((total_height - top_margin - header_h) * scale)
        box_w = int(self.box_w * scale)
        box_h = int(header_h * scale)

        # 1. Lifelines
        for x in self.p_coords:
            X = int(x * scale)
            draw.line([(X, top_box_y + box_h // 2), (X, bot_box_y + box_h // 2)], fill=LIFELINE_COLOR, width=int(2 * scale))

        # 2. Layout Elements
        for el in layout_elements:
            if el["type"] == "span":
                sy = int(el["y"] * scale)
                sh = int(el["height"] * scale)
                m = int(18 * scale)
                style = SPANS.get(el["style"], SPANS["info"])
                draw.rounded_rectangle([(m, sy), (W - m, sy + sh)], radius=int(4 * scale), fill=style["bg"])
                
                txt = el["text"]
                bb = draw.textbbox((0, 0), txt, font=f_span)
                tw, th = bb[2] - bb[0], bb[3] - bb[1]
                draw.text(((W - tw) // 2, sy + (sh - th) // 2 - int(1.5 * scale)), txt, fill=style["text"], font=f_span)

            elif el["type"] == "note":
                px = int(self.p_coords[el["p_idx"]] * scale)
                ny = int(el["y"] * scale)
                nw = int(el["width"] * scale)
                nh = int(el["height"] * scale)
                pad_v = int(el["pad_v"] * scale)
                line_h = int(el["line_h"] * scale)

                th_cfg = THEMES.get(el["theme"], THEMES["neutral"])

                left = px - nw // 2
                right = px + nw // 2
                draw.rounded_rectangle([(left, ny), (right, ny + nh)], radius=int(4 * scale), fill=th_cfg["note_bg"], outline=th_cfg["note_border"], width=int(1.5 * scale))

                curr_text_y = ny + pad_v
                for line in el["lines"]:
                    f = f_note_bold if line.startswith("# ") else f_note
                    disp = line[2:] if line.startswith("# ") else line
                    bb = draw.textbbox((0, 0), disp, font=f)
                    tw = bb[2] - bb[0]
                    draw.text((px - tw // 2, curr_text_y), disp, fill=th_cfg["note_text"], font=f)
                    curr_text_y += line_h

            elif el["type"] == "message":
                x1 = int(self.p_coords[el["from_p"]] * scale)
                x2 = int(self.p_coords[el["to_p"]] * scale)
                ay = int(el["arrow_y"] * scale)

                # Arrow line
                draw.line([(x1, ay), (x2, ay)], fill=ARROW_COLOR, width=int(1.5 * scale))

                # Arrowhead
                hlen = int(9 * scale)
                hw = int(4.5 * scale)
                if x2 > x1:
                    draw.polygon([(x2, ay), (x2 - hlen, ay - hw), (x2 - hlen, ay + hw)], fill=ARROW_COLOR)
                else:
                    draw.polygon([(x2, ay), (x2 + hlen, ay - hw), (x2 + hlen, ay + hw)], fill=ARROW_COLOR)

                # Numbered circle
                if el["step_num"] is not None:
                    cr = int(9 * scale)
                    cx = x1 + int((22 if x2 > x1 else -22) * scale)
                    draw.ellipse([(cx - cr, ay - cr), (cx + cr, ay + cr)], fill=CIRCLE_BG)
                    st_str = str(el["step_num"])
                    bb = draw.textbbox((0, 0), st_str, font=f_num)
                    tw, th = bb[2] - bb[0], bb[3] - bb[1]
                    draw.text((cx - tw // 2, ay - th // 2 - int(1.5 * scale)), st_str, fill=CIRCLE_TEXT, font=f_num)

                # Label above arrow (centered)
                lbl = el["label"]
                bb = draw.textbbox((0, 0), lbl, font=f_arrow)
                tw, th = bb[2] - bb[0], bb[3] - bb[1]
                mid_x = (x1 + x2) // 2
                draw.text((mid_x - tw // 2, ay - th - int(5 * scale)), lbl, fill=ARROW_TEXT, font=f_arrow)

                # Payload box below arrow
                pl = el["payload"]
                if pl:
                    py = int(pl["y"] * scale)
                    pw = int(pl["width"] * scale)
                    ph = int(pl["height"] * scale)
                    pad_v = int(pl["pad_v"] * scale)
                    line_h = int(pl["line_h"] * scale)
                    
                    box_left = mid_x - pw // 2
                    box_right = mid_x + pw // 2
                    draw.rounded_rectangle([(box_left, py), (box_right, py + ph)], radius=int(4 * scale), fill=PAYLOAD_BG, outline=PAYLOAD_BORDER, width=int(1 * scale))

                    curr_text_y = py + pad_v
                    for line in pl["lines"]:
                        bb = draw.textbbox((0, 0), line, font=f_note)
                        tw = bb[2] - bb[0]
                        draw.text((mid_x - tw // 2, curr_text_y), line, fill=PAYLOAD_TEXT, font=f_note)
                        curr_text_y += line_h

        # 3. Participant header and footer boxes
        for i, name in enumerate(self.participants):
            px = int(self.p_coords[i] * scale)
            th_cfg = THEMES.get(self.p_themes[i], THEMES["neutral"])
            for py in [top_box_y, bot_box_y]:
                left = px - box_w // 2
                draw.rounded_rectangle(
                    [(left, py), (left + box_w, py + box_h)],
                    radius=int(6 * scale),
                    fill=th_cfg["header_bg"],
                    outline=th_cfg["header_border"],
                    width=int(1.5 * scale)
                )
                bb = draw.textbbox((0, 0), name, font=f_part)
                tw, th = bb[2] - bb[0], bb[3] - bb[1]
                draw.text((px - tw // 2, py + (box_h - th) // 2 - int(2 * scale)), name, fill=th_cfg["header_text"], font=f_part)

        img.save(filename)
        print(f"Saved PNG: {filename}")

    def render_svg(self, filename):
        layout_elements, total_height, top_margin, header_h = self._compute_layout()

        svg = []
        svg.append(f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {self.width} {total_height}" width="{self.width}" height="{total_height}">')
        svg.append('<defs>')
        svg.append('<style>')
        svg.append('text { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; }')
        svg.append('.lifeline { stroke: #cbd5e1; stroke-width: 2; }')
        svg.append('.arrow-line { stroke: #1e293b; stroke-width: 1.5; }')
        svg.append('.arrow-text { font-size: 12px; font-weight: 500; fill: #0f172a; text-anchor: middle; }')
        svg.append('.circle-bg { fill: #1e293b; }')
        svg.append('.circle-text { font-size: 10.5px; font-weight: bold; fill: #ffffff; text-anchor: middle; dominant-baseline: central; }')
        svg.append('.payload-box { fill: #1e293b; stroke: #0f172a; stroke-width: 1; rx: 4; }')
        svg.append('.payload-text { font-size: 11px; fill: #f8fafc; text-anchor: middle; dominant-baseline: central; }')
        svg.append('</style>')
        svg.append('</defs>')
        svg.append(f'<rect width="{self.width}" height="{total_height}" fill="{BG_COLOR}"/>')

        top_box_y = top_margin
        bot_box_y = total_height - top_margin - header_h
        box_w = self.box_w
        box_h = header_h

        # 1. Lifelines
        for x in self.p_coords:
            svg.append(f'<line class="lifeline" x1="{x}" y1="{top_box_y + box_h // 2}" x2="{x}" y2="{bot_box_y + box_h // 2}"/>')

        # 2. Elements
        for el in layout_elements:
            if el["type"] == "span":
                sy = el["y"]
                sh = el["height"]
                m = 18
                style = SPANS.get(el["style"], SPANS["info"])
                svg.append(f'<rect x="{m}" y="{sy}" width="{self.width - 2 * m}" height="{sh}" rx="4" fill="{style["bg"]}"/>')
                svg.append(f'<text x="{self.width // 2}" y="{sy + sh // 2}" font-size="11px" font-weight="bold" fill="{style["text"]}" text-anchor="middle" dominant-baseline="central">{el["text"]}</text>')

            elif el["type"] == "note":
                px = self.p_coords[el["p_idx"]]
                ny = el["y"]
                nw = el["width"]
                nh = el["height"]
                pad_v = el["pad_v"]
                line_h = el["line_h"]
                th_cfg = THEMES.get(el["theme"], THEMES["neutral"])
                left = px - nw // 2
                svg.append(f'<rect x="{left}" y="{ny}" width="{nw}" height="{nh}" rx="4" fill="{th_cfg["note_bg"]}" stroke="{th_cfg["note_border"]}" stroke-width="1.5"/>')
                curr_text_y = ny + pad_v + line_h // 2
                for line in el["lines"]:
                    bold = ' font-weight="bold"' if line.startswith("# ") else ''
                    disp = line[2:] if line.startswith("# ") else line
                    svg.append(f'<text x="{px}" y="{curr_text_y}" font-size="11px"{bold} fill="{th_cfg["note_text"]}" text-anchor="middle" dominant-baseline="central">{disp}</text>')
                    curr_text_y += line_h

            elif el["type"] == "message":
                x1 = self.p_coords[el["from_p"]]
                x2 = self.p_coords[el["to_p"]]
                ay = el["arrow_y"]
                svg.append(f'<line class="arrow-line" x1="{x1}" y1="{ay}" x2="{x2}" y2="{ay}"/>')
                hlen = 8
                hw = 4
                if x2 > x1:
                    svg.append(f'<polygon points="{x2},{ay} {x2 - hlen},{ay - hw} {x2 - hlen},{ay + hw}" fill="{ARROW_COLOR}"/>')
                else:
                    svg.append(f'<polygon points="{x2},{ay} {x2 + hlen},{ay - hw} {x2 + hlen},{ay + hw}" fill="{ARROW_COLOR}"/>')

                if el["step_num"] is not None:
                    cx = x1 + (22 if x2 > x1 else -22)
                    svg.append(f'<circle class="circle-bg" cx="{cx}" cy="{ay}" r="9"/>')
                    svg.append(f'<text class="circle-text" x="{cx}" y="{ay}">{el["step_num"]}</text>')

                mid_x = (x1 + x2) // 2
                svg.append(f'<text class="arrow-text" x="{mid_x}" y="{ay - 5}">{el["label"]}</text>')

                pl = el["payload"]
                if pl:
                    py = pl["y"]
                    pw = pl["width"]
                    ph = pl["height"]
                    pad_v = pl["pad_v"]
                    line_h = pl["line_h"]
                    box_left = mid_x - pw // 2
                    svg.append(f'<rect class="payload-box" x="{box_left}" y="{py}" width="{pw}" height="{ph}"/>')
                    curr_text_y = py + pad_v + line_h // 2
                    for line in pl["lines"]:
                        svg.append(f'<text class="payload-text" x="{mid_x}" y="{curr_text_y}">{line}</text>')
                        curr_text_y += line_h

        # 3. Participants
        for i, name in enumerate(self.participants):
            px = self.p_coords[i]
            th_cfg = THEMES.get(self.p_themes[i], THEMES["neutral"])
            for py in [top_box_y, bot_box_y]:
                left = px - box_w // 2
                svg.append(f'<rect x="{left}" y="{py}" width="{box_w}" height="{box_h}" rx="6" fill="{th_cfg["header_bg"]}" stroke="{th_cfg["header_border"]}" stroke-width="1.5"/>')
                svg.append(f'<text x="{px}" y="{py + box_h // 2}" font-size="13.5px" font-weight="bold" fill="{th_cfg["header_text"]}" text-anchor="middle" dominant-baseline="central">{name}</text>')

        svg.append('</svg>')
        with open(filename, "w", encoding="utf-8") as f:
            f.write("\n".join(svg))
        print(f"Saved SVG: {filename}")


# ==============================================================================
# 1. FIG 1: TLS 1.3 Handshake & Certificate Pinning
# ==============================================================================
def make_fig1_handshake():
    d = FlowDiagram(width=660, participants=["Client", "Server"], p_themes=["client", "server"], box_w=150)
    
    d.add_note(0, [
        "Genera coppia di chiavi effimere",
        "(ECDH) e un nonce casuale"
    ], width=215)

    d.add_message(0, 1, "Client Hello", payload_lines=[
        "Chiave pubblica effimera +",
        "nonce client + ciphers TLS 1.3"
    ], step_num=1, payload_width=220)

    d.add_note(1, [
        "Genera a sua volta coppia di",
        "chiavi effimere (ECDH) e nonce"
    ], width=215)

    d.add_note(1, [
        "Combina le chiavi pubbliche (ECDH)",
        "per ottenere il segreto condiviso,",
        "da cui deriva la session key (HKDF)"
    ], width=230)

    d.add_note(1, [
        "Firma l'intero transcript dello",
        "scambio con la propria chiave privKc",
        "e cifra la firma con la session key"
    ], width=235)

    d.add_message(1, 0, "Server Hello", payload_lines=[
        "Chiave pubblica effimera + nonce server +",
        "certificato (pubKc) + firma cifrata scambio"
    ], step_num=2, payload_width=255)

    d.add_note(0, [
        "Verifica il certificato del server",
        "(pinning su server_conn.crt e SAN)"
    ], width=225)

    d.add_note(0, [
        "Calcola lo stesso segreto condiviso",
        "(ECDH) e deriva la session key (HKDF)"
    ], width=230)

    d.add_note(0, [
        "Verifica la firma con la session key",
        "e la validità su transcript, confermando",
        "l'autenticità del server"
    ], width=235)

    d.add_span("Handshake completato: entrambi condividono la stessa session key per il canale cifrato", style="info", height=32)

    base = os.path.join(OUTPUT_DIR, "fig1_handshake_protocol")
    d.render_png(f"{base}.png")
    d.render_svg(f"{base}.svg")


# ==============================================================================
# 2. FIG 2: Login & Authentication Protocol
# ==============================================================================
def make_fig2_login():
    d = FlowDiagram(width=660, participants=["Client di Alice", "Server"], p_themes=["client", "server"], box_w=160)

    d.add_span("Canale sicuro già stabilito (handshake TLS 1.3 completato)", style="info", height=32)

    d.add_note(0, [
        "Genera nonce crittografico",
        "del client Nc (16B CSPRNG)"
    ], width=205)

    d.add_message(0, 1, 'Login (email/username + password)', payload_lines=[
        '{"cmd": "LOGIN", "username": "alice",',
        '"password": "...", "nonce_c": "Nc"}'
    ], step_num=1, payload_width=245)

    d.add_note(1, [
        "Verifica le credenziali in memoria",
        "(g_users, caricato da users.json)",
        "(confronto SHA-256(pass || salt))"
    ], width=225)

    d.add_note(1, [
        "Genera nonce server Ns (16B),",
        "inizializza sessione autenticata",
        "e contatore expected_seq = 1"
    ], width=225)

    d.add_message(1, 0, "Login riuscito", payload_lines=[
        '{"status": "OK", "nonce_s": "Ns"}'
    ], step_num=2, payload_width=210)

    d.add_note(0, [
        "Memorizza il nonce Ns,",
        "inizializza contatore seq = 1 e",
        "apre la shell interattiva REPL"
    ], width=220)

    d.add_span("Autenticazione riuscita: sessione protetta da attacchi Replay", style="success", height=32)

    base = os.path.join(OUTPUT_DIR, "fig2_login_flow")
    d.render_png(f"{base}.png")
    d.render_svg(f"{base}.svg")


# ==============================================================================
# 3. FIG 3: Timestamp Request & Issuance (Happy Path)
# ==============================================================================
def make_fig3_timestamp_happy():
    d = FlowDiagram(width=660, participants=["Client di Alice", "Server"], p_themes=["client", "server"], box_w=160)

    d.add_span("Canale sicuro TLS 1.3 attivo - Sessione utente autenticata", style="info", height=32)

    d.add_note(0, [
        "Calcola l'hash del documento con",
        "SHA-256 (256 bit / 32 Byte locale)",
        "(Data Minimization: nessun invio file)"
    ], width=240)

    d.add_message(0, 1, "Richiesta di timestamp sull'hash calcolato", payload_lines=[
        '{"cmd": "TIMESTAMP",',
        '"hash": "h_sha256",',
        '"nonce_s": "Ns", "seq": 1}'
    ], step_num=1, payload_width=230)

    d.add_note(1, [
        "Verifica anti-replay/sessione:",
        "nonce_s == Ns e seq == expected_seq,",
        "incrementa expected_seq = 2"
    ], width=245)

    d.add_note(1, [
        "Verifica i crediti residui",
        "di Alice in users.json (nr > 0)"
    ], width=205)

    d.add_note(1, [
        "Scala un credito ad Alice (nr=99, nc=1)",
        "e persiste lo stato su users.json"
    ], width=240)

    d.add_note(1, [
        "Campiona Unix timestamp UTC (t),",
        "costruisce payload canonico (40B)",
        "e firma con privKts (ECDSA P-384)"
    ], width=235)

    d.add_message(1, 0, "Token emesso (hash, time, firma)", payload_lines=[
        '{"status": "OK", "hash": "h",',
        '"time": t, "signature": "σ",',
        '"nc": 1, "nr": 99,',
        '"nonce_s": "Ns", "seq": 1}'
    ], step_num=2, payload_width=230)

    d.add_note(0, [
        "Verifica immediata del token con pubKts",
        "e salvataggio in token_<h>.json"
    ], width=235)

    d.add_span("Token valido: verificabile in futuro da chiunque possieda pubKts", style="success", height=32)

    base = os.path.join(OUTPUT_DIR, "fig3_timestamp_request")
    d.render_png(f"{base}.png")
    d.render_svg(f"{base}.svg")


# ==============================================================================
# 4. FIG 4: Edge Cases: Quota Exhaustion & Replay Attack
# ==============================================================================
def make_fig4_edge_cases():
    d = FlowDiagram(width=660, participants=["Client", "Server"], p_themes=["client", "server"], box_w=150)

    d.add_span("Caso 1: Quota di Timestamp Esaurita (Utente Charlie, nr = 0)", style="warning", height=32)

    d.add_message(0, 1, "Richiesta timestamp con crediti esauriti", payload_lines=[
        '{"cmd": "TIMESTAMP", "hash": "h",',
        '"nonce_s": "Ns", "seq": 1}'
    ], step_num=1, payload_width=260)

    d.add_note(1, [
        "Verifica nonce_s == Ns e seq == 1",
        "Rileva crediti residui nr == 0 in users.json",
        "Rifiuta la richiesta senza scalare crediti"
    ], width=250)

    d.add_message(1, 0, "Notifica errore quota esaurita", payload_lines=[
        '{"status": "ERROR",',
        '"message": "Timestamp balance exhausted",',
        '"nonce_s": "Ns", "seq": 1}'
    ], step_num=2, payload_width=270)

    d.add_note(0, [
        "Operazione respinta:",
        "nessuna firma o token rilasciato"
    ], width=210)

    d.add_span("Caso 2: Tentativo di Replay Attack (Messaggio duplicato o seq già usato)", style="error", height=32)

    d.add_message(0, 1, "Replay frame con seq già consumato", payload_lines=[
        '{"cmd": "TIMESTAMP", "hash": "h",',
        '"nonce_s": "Ns", "seq": 1}'
    ], step_num=3, payload_width=260)

    d.add_note(1, [
        "Rileva seq mismatch (1 != expected 2)",
        "Segnala violazione di sicurezza",
        "Interrompe immediatamente la sessione"
    ], width=240)

    d.add_message(1, 0, "[Chiusura immediata della connessione TLS]", step_num=4)

    base = os.path.join(OUTPUT_DIR, "fig4_edge_cases")
    d.render_png(f"{base}.png")
    d.render_svg(f"{base}.svg")


# ==============================================================================
# 5. FIG 5: Offline Verification (tss_verify)
# ==============================================================================
def make_fig5_offline_verify():
    d = FlowDiagram(width=660, participants=["Auditor / Utente", "Tool Offline (tss_verify)"], p_themes=["auditor", "tool"], box_w=185)

    d.add_span("Verifica 100% Offline (Nessuna connessione di rete, nessuna credenziale)", style="info", height=32)

    d.add_note(0, [
        "Possiede token.json,",
        "chiave pubblica server_ts.pub",
        "e file originale (opzionale)"
    ], width=210)

    d.add_message(0, 1, "Esegue comando di verifica locale", payload_lines=[
        "tss_verify server_ts.pub",
        "token_<h>.json [documento.pdf]"
    ], step_num=1, payload_width=220)

    d.add_note(1, [
        "Carica la chiave pubblica",
        "della TSA server_ts.pub (P-384)"
    ], width=205)

    d.add_note(1, [
        "Parsing token.json ed estrazione",
        "dei campi <hash, time, signature>"
    ], width=215)

    d.add_note(1, [
        "(Se fornito file) Calcola SHA-256 locale",
        "e verifica che coincida con hash del token"
    ], width=245)

    d.add_note(1, [
        "Ricostruisce payload canonico (40B):",
        "hash (32B) || time_be64 (8B)"
    ], width=230)

    d.add_note(1, [
        "Verifica firma crittografica ECDSA",
        "tramite EVP_DigestVerify con pubKts"
    ], width=230)

    d.add_message(1, 0, "Esito verifica su stdout", payload_lines=[
        "[OK] Token is CRYPTOGRAPHICALLY VALID",
        "UTC Time: 2026-09-01 14:30:00"
    ], step_num=2, payload_width=250)

    d.add_note(0, [
        "Prova matematica inconfutabile:",
        "il documento esisteva inalterato",
        "all'istante t certificato dalla TSA"
    ], width=220)

    d.add_span("Verifica completata: Integrità e datazione opponibili a terzi", style="success", height=32)

    base = os.path.join(OUTPUT_DIR, "fig5_offline_verification")
    d.render_png(f"{base}.png")
    d.render_svg(f"{base}.svg")


# ==============================================================================
# 6. Dedicated Diagram: Weak Hash Rejection (e.g. MD5)
# ==============================================================================
def make_fig_weak_hash_md5():
    d = FlowDiagram(width=660, participants=["Client", "Server"], p_themes=["client", "server"], box_w=160)

    d.add_span("Canale sicuro TLS 1.3 attivo - Sessione utente autenticata", style="info", height=32)

    d.add_note(0, [
        "Tentativo con hash debole (MD5):",
        "Digest 128 bit (32 caratteri hex)",
        "(Soggetto ad attacchi di collisione)"
    ], width=250)

    d.add_message(0, 1, "Richiesta con hash debole (MD5)", payload_lines=[
        '{"cmd": "TIMESTAMP",',
        '"hash": "c4ca4238a0b92382... (32 hex)",',
        '"nonce_s": "Ns", "seq": 1}'
    ], step_num=1, payload_width=270)

    d.add_note(1, [
        "Verifica anti-replay/sessione:",
        "nonce_s == Ns e seq == expected_seq,",
        "incrementa expected_seq = 2"
    ], width=245)

    d.add_note(1, [
        "Validazione sintattica dell'hash:",
        "doc_hash.length() == 32 (non 64 hex)",
        "Rifiuto: non conforme a SHA-256"
    ], width=250)

    d.add_note(1, [
        "Protezione servizio e contabilità:",
        "Nessuna firma digitale con privKts,",
        "crediti utente intatti (nr invariato)"
    ], width=250)

    d.add_message(1, 0, "Rifiuto immediato (formato errato)", payload_lines=[
        '{"status": "ERROR",',
        '"message": "Formato hash non valido",',
        '"nonce_s": "Ns", "seq": 1}'
    ], step_num=2, payload_width=265)

    d.add_note(0, [
        "Richiesta respinta dal server.",
        "Il servizio impone SHA-256 per",
        "garantire il pieno valore legale"
    ], width=235)

    d.add_span("Sicurezza garantita: Rifiutati algoritmi deboli soggetti ad attacchi di collisione", style="warning", height=32)

    base = os.path.join(OUTPUT_DIR, "fig_weak_hash_rejection")
    d.render_png(f"{base}.png")
    d.render_svg(f"{base}.svg")


# ==============================================================================
# 7. Dedicated Diagram: Quota Exhaustion (e.g. Charlie, nr == 0)
# ==============================================================================
def make_fig_quota_exhausted():
    d = FlowDiagram(width=660, participants=["Client di Charlie", "Server"], p_themes=["client", "server"], box_w=160)

    d.add_span("Canale sicuro TLS 1.3 attivo - Sessione autenticata (Charlie)", style="info", height=32)

    d.add_note(0, [
        "Calcola l'hash SHA-256 del documento",
        "(256 bit / 32 Byte = 64 caratteri hex)",
        "(Data Minimization: nessun invio file)"
    ], width=245)

    d.add_message(0, 1, "Richiesta di timestamp con saldo esaurito", payload_lines=[
        '{"cmd": "TIMESTAMP",',
        '"hash": "1b4f68b852...240f5c6b",',
        '"nonce_s": "Ns", "seq": 1}'
    ], step_num=1, payload_width=255)

    d.add_note(1, [
        "Verifica nonce_s == Ns e seq == 1,",
        "incrementa expected_seq = 2"
    ], width=235)

    d.add_note(1, [
        "Controllo quota in RAM (g_users):",
        "Charlie: nc = 10, nr = 0 (esauriti)",
        "Saldo crediti insufficiente!"
    ], width=245)

    d.add_note(1, [
        "Nessun calcolo crittografico (privKts),",
        "nessuna modifica su users.json"
    ], width=240)

    d.add_message(1, 0, "Rifiuto richiesta per quota esaurita", payload_lines=[
        '{"status": "ERROR",',
        '"message": "Timestamp balance exhausted",',
        '"nonce_s": "Ns", "seq": 1}'
    ], step_num=2, payload_width=255)

    d.add_note(0, [
        "Notifica quota esaurita ricevuta.",
        "Nessun token rilasciato o salvato.",
        "L'utente deve acquistare nuovi crediti"
    ], width=245)

    d.add_span("Controllo quote applicato: Emissione bloccata in assenza di crediti residui", style="warning", height=32)

    base = os.path.join(OUTPUT_DIR, "fig_quota_exhausted")
    d.render_png(f"{base}.png")
    d.render_svg(f"{base}.svg")


if __name__ == "__main__":
    make_fig1_handshake()
    make_fig2_login()
    make_fig3_timestamp_happy()
    make_fig4_edge_cases()
    make_fig5_offline_verify()
    make_fig_weak_hash_md5()
    make_fig_quota_exhausted()
    print("All diagrams generated successfully in figures/")
