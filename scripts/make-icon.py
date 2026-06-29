#!/usr/bin/env python3
"""Generate a 1024x1024 macOS-style app icon for gmacFTP.

Motif: a "squircle" app-tile background (near-black #0A0B0E) holding two
file-pane cards with a bold accent (#007AFF) transfer arrow between them —
the classic FTP two-pane / connected-transfer metaphor, in a clean modern
style. All drawing is ASCII-safe vector geometry via PIL.
"""
from PIL import Image, ImageDraw, ImageFilter
import os
import math

SIZE = 1024
ACCENT = (0, 122, 255, 255)        # #007AFF
ACCENT_BRIGHT = (60, 160, 255, 255)
BG_DEEP = (10, 11, 14, 255)        # #0A0B0E near-black
BG_TILE = (22, 24, 30, 255)        # slightly lifted tile face
CARD = (38, 42, 52, 255)           # file-pane card
CARD_HI = (54, 60, 74, 255)        # card top highlight
LINE_DIM = (88, 96, 114, 255)
WHITE = (245, 247, 252, 255)
WHITE_DIM = (200, 206, 218, 255)

# Apple "squircle" rounded rect is squircle-y; a plain rounded rectangle at
# radius ~22.37% of the side reads as a macOS app tile.
CORNER = int(SIZE * 0.2237)


def squircle_mask(size, radius):
    """Anti-aliased rounded-square mask via supersampling."""
    SS = 4
    big = size * SS
    r = radius * SS
    img = Image.new("L", (big, big), 0)
    d = ImageDraw.Draw(img)
    d.rounded_rectangle([0, 0, big - 1, big - 1], radius=r, fill=255)
    return img.resize((size, size), Image.LANCZOS)


def draw_tile_base(d, size, radius):
    # Filled rounded tile (deep background). We draw onto RGBA then mask later.
    d.rounded_rectangle([0, 0, size - 1, size - 1], radius=radius, fill=BG_DEEP)
    # Subtle radial-ish vignette: a darker frame and a brighter center via
    # concentric rounded rects with low alpha.
    for i in range(8):
        a = 10 - i
        if a <= 0:
            break
        inset = 6 + i * 6
        d.rounded_rectangle(
            [inset, inset, size - 1 - inset, size - 1 - inset],
            radius=max(2, radius - inset),
            outline=(40 + i * 3, 46 + i * 3, 60 + i * 3, a),
        )


def card(d, box, radius):
    x0, y0, x1, y1 = box
    # shadow
    sh = Image.new("RGBA", (x1 - x0 + 40, y1 - y0 + 40), (0, 0, 0, 0))
    sd = ImageDraw.Draw(sh)
    sd.rounded_rectangle(
        [20, 22, (x1 - x0) + 20, (y1 - y0) + 22], radius=radius, fill=(0, 0, 0, 150)
    )
    sh = sh.filter(ImageFilter.GaussianBlur(18))
    base = Image.new("RGBA", (SIZE, SIZE), (0, 0, 0, 0))
    base.alpha_composite(sh, (x0 - 20, y0 - 20))
    # card body
    d.rounded_rectangle([x0, y0, x1, y1], radius=radius, fill=CARD)
    # top highlight bar
    d.rounded_rectangle(
        [x0, y0, x1, y0 + int((y1 - y0) * 0.16)],
        radius=radius,
        fill=CARD_HI,
    )
    d.rectangle([x0, y0 + int((y1 - y0) * 0.12), x1, y0 + int((y1 - y0) * 0.16)], fill=CARD_HI)
    return base


def file_rows(d, box, rows=4):
    x0, y0, x1, y1 = box
    pad = int((x1 - x0) * 0.10)
    top = y0 + int((y1 - y0) * 0.22)
    row_h = (y1 - top - pad) // rows
    for i in range(rows):
        ry = top + pad + i * row_h + row_h // 2
        # folder/file glyph (small rounded rect "icon")
        gw = int((x1 - x0) * 0.10)
        gh = int(row_h * 0.45)
        gx = x0 + pad
        gy = ry - gh // 2
        col = ACCENT if i == rows - 1 else LINE_DIM
        d.rounded_rectangle([gx, gy, gx + gw, gy + gh], radius=gh // 3, fill=col)
        # text line
        lw = int((x1 - x0) * (0.55 if i % 2 == 0 else 0.40))
        lh = max(4, gh // 3)
        d.rounded_rectangle(
            [gx + gw + pad, ry - lh // 2, gx + gw + pad + lw, ry + lh // 2 + lh % 2],
            radius=lh,
            fill=WHITE if i == 0 else WHITE_DIM,
        )


def arrow(d, cx, cy, w, h, color, direction="right"):
    """Bold right-pointing transfer arrow, rounded joins."""
    half_w = w / 2
    half_h = h / 2
    stem_w = w * 0.34
    if direction == "right":
        # shaft rectangle
        d.rounded_rectangle(
            [cx - half_w, cy - stem_w / 2, cx + half_w * 0.35, cy + stem_w / 2],
            radius=stem_w / 2,
            fill=color,
        )
        # head triangle (rounded)
        head = [
            (cx + half_w * 0.15, cy - half_h),
            (cx + half_w, cy),
            (cx + half_w * 0.15, cy + half_h),
        ]
        d.polygon(head, fill=color)
        # round the head tip with a circle
        tr = stem_w / 2
        d.ellipse(
            [cx + half_w * 0.15 - tr, cy - half_h - tr * 0.2,
             cx + half_w * 0.15 + tr, cy + half_h + tr * 0.2],
            fill=color,
        )
    else:
        d.rounded_rectangle(
            [cx - half_w * 0.35, cy - stem_w / 2, cx + half_w, cy + stem_w / 2],
            radius=stem_w / 2,
            fill=color,
        )
        head = [
            (cx - half_w * 0.15, cy - half_h),
            (cx - half_w, cy),
            (cx - half_w * 0.15, cy + half_h),
        ]
        d.polygon(head, fill=color)


def build():
    img = Image.new("RGBA", (SIZE, SIZE), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)
    draw_tile_base(d, SIZE, CORNER)

    # Two file-pane cards, slightly overlapping vertically offset for depth.
    margin_x = int(SIZE * 0.155)
    gap = int(SIZE * 0.045)
    card_w = (SIZE - 2 * margin_x - gap) // 2
    card_top = int(SIZE * 0.235)
    card_h = int(SIZE * 0.535)
    left_box = [margin_x, card_top, margin_x + card_w, card_top + card_h]
    right_box = [margin_x + card_w + gap, card_top, margin_x + 2 * card_w + gap, card_top + card_h]

    card_radius = int(card_w * 0.09)
    # Draw shadows then bodies directly on main draw for crispness.
    for box in (left_box, right_box):
        x0, y0, x1, y1 = box
        sh = Image.new("RGBA", (x1 - x0 + 60, y1 - y0 + 60), (0, 0, 0, 0))
        sd = ImageDraw.Draw(sh)
        sd.rounded_rectangle([30, 34, (x1 - x0) + 30, (y1 - y0) + 34],
                             radius=card_radius, fill=(0, 0, 0, 170))
        sh = sh.filter(ImageFilter.GaussianBlur(20))
        img.alpha_composite(sh, (x0 - 30, y0 - 30))

    for box in (left_box, right_box):
        x0, y0, x1, y1 = box
        d.rounded_rectangle(box, radius=card_radius, fill=CARD)
        # title bar
        tb_h = int((y1 - y0) * 0.15)
        d.rounded_rectangle([x0, y0, x1, y0 + tb_h], radius=card_radius, fill=CARD_HI)
        d.rectangle([x0, y0 + tb_h - card_radius, x1, y0 + tb_h], fill=CARD_HI)
        # window dots
        dot_r = int((x1 - x0) * 0.013)
        dy = y0 + tb_h // 2
        for k, col in enumerate([(255, 95, 86, 255), (255, 189, 46, 255), (39, 201, 63, 255)]):
            dx = x0 + int((x1 - x0) * 0.07) + k * (dot_r * 3)
            d.ellipse([dx - dot_r, dy - dot_r, dx + dot_r, dy + dot_r], fill=col)
        file_rows(d, box)

    # Transfer arrow between panes — accent, bold, centered.
    cx = (left_box[2] + right_box[0]) // 2 + (right_box[0] - left_box[2]) // 2
    cy = (card_top + (card_top + card_h)) // 2 + int(card_h * 0.02)
    a_w = int(SIZE * 0.20)
    a_h = int(SIZE * 0.135)
    # glow underlay
    glow = Image.new("RGBA", (SIZE, SIZE), (0, 0, 0, 0))
    gd = ImageDraw.Draw(glow)
    arrow(gd, cx, cy, a_w * 1.25, a_h * 1.25, (*ACCENT_BRIGHT[:3], 90), "right")
    glow = glow.filter(ImageFilter.GaussianBlur(22))
    img.alpha_composite(glow)
    # crisp arrow
    arrow(d, cx, cy, a_w, a_h, ACCENT, "right")

    # Accent ring on the tile edge for a finished macOS look.
    d.rounded_rectangle(
        [3, 3, SIZE - 4, SIZE - 4], radius=CORNER,
        outline=(70, 130, 220, 60), width=2,
    )

    # Apply squircle mask (fully transparent outside the tile).
    mask = squircle_mask(SIZE, CORNER)
    out = Image.new("RGBA", (SIZE, SIZE), (0, 0, 0, 0))
    out.paste(img, (0, 0), mask)
    return out


def main():
    icon = build()
    assets = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "assets")
    os.makedirs(assets, exist_ok=True)

    full = os.path.join(assets, "icon-1024.png")
    icon.save(full, "PNG")

    # 512 preview
    icon.resize((512, 512), Image.LANCZOS).save(
        os.path.join(assets, "icon-preview.png"), "PNG"
    )
    print("wrote", full)


if __name__ == "__main__":
    main()
