# -*- coding: utf-8 -*-
"""生成高品质应用图标 deploy/adm.ico（多尺寸），无外部素材依赖。

设计：对角渐变圆角方（深蓝→科技蓝→亮青）+ 顶部玻璃高光 + 白色盾牌（安全）
      + 盾牌内「目录树」符号（AD 目录服务意象）+ 右下角绿色「在线」状态点。
"""
import os

from PIL import Image, ImageDraw, ImageFilter

OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'adm.ico')
SIZE = 256

# 对角渐变三段色
C_TOP = (30, 64, 175)      # 深蓝
C_MID = (59, 130, 246)     # 科技蓝
C_BOT = (56, 189, 248)     # 亮青


def _grad(px, py, s):
    """对角渐变：t 从 0(左上) 到 1(右下)，三段线性插值。"""
    t = (px + py) / (2 * max(1, s - 1))
    if t < 0.5:
        a, b, k = C_TOP, C_MID, t / 0.5
    else:
        a, b, k = C_MID, C_BOT, (t - 0.5) / 0.5
    return tuple(int(a[i] + (b[i] - a[i]) * k) for i in range(3))


def make(size: int) -> Image.Image:
    s = size
    img = Image.new('RGBA', (s, s), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)

    # 1. 渐变背景（先画满，再套圆角蒙版）
    for y in range(s):
        for x in range(s):
            d.point((x, y), fill=_grad(x, y, s) + (255,))

    radius = int(s * 0.22)
    mask = Image.new('L', (s, s), 0)
    ImageDraw.Draw(mask).rounded_rectangle([0, 0, s - 1, s - 1], radius=radius, fill=255)
    img.putalpha(mask)

    # 2. 顶部玻璃高光（半透明白色椭圆，向下渐隐）
    hl = Image.new('RGBA', (s, s), (0, 0, 0, 0))
    hd = ImageDraw.Draw(hl)
    hd.ellipse([-s * 0.18, -s * 0.30, s * 1.18, s * 0.42], fill=(255, 255, 255, 46))
    hl = hl.filter(ImageFilter.GaussianBlur(s * 0.04))
    img = Image.alpha_composite(img, hl)
    d = ImageDraw.Draw(img)

    # 3. 白色盾牌（安全意象）：顶边 + 两侧直边 + 底部圆弧（二次贝塞尔），经典盾形
    cx = s * 0.50
    sh_top = s * 0.26
    sh_bottom = s * 0.76
    sh_mid = sh_top + (sh_bottom - sh_top) * 0.45
    sh_half_w = s * 0.20
    steps = 28
    pts = [(cx - sh_half_w, sh_top), (cx + sh_half_w, sh_top),
           (cx + sh_half_w, sh_mid)]
    for i in range(1, steps + 1):          # 右下弧：右中 → 底部中心
        t = i / steps
        x = (1 - t) ** 2 * (cx + sh_half_w) + 2 * (1 - t) * t * (cx + sh_half_w) + t ** 2 * cx
        y = (1 - t) ** 2 * sh_mid + 2 * (1 - t) * t * (sh_bottom - s * 0.02) + t ** 2 * sh_bottom
        pts.append((x, y))
    for i in range(steps):                 # 左下弧：底部中心 → 左中
        t = 1 - i / steps
        x = (1 - t) ** 2 * (cx - sh_half_w) + 2 * (1 - t) * t * (cx - sh_half_w) + t ** 2 * cx
        y = (1 - t) ** 2 * sh_mid + 2 * (1 - t) * t * (sh_bottom - s * 0.02) + t ** 2 * sh_bottom
        pts.append((x, y))
    d.polygon(pts, fill=(255, 255, 255, 242))
    d.line(pts + [pts[0]], fill=(219, 234, 254, 255), width=max(1, s // 96), joint='curve')

    # 4. 盾牌内「目录树」符号：中心节点 + 上、下两个分支节点，连线
    node_r = s * 0.030
    tree_c = (int(cx), int(sh_top + s * 0.16))
    tree_u = (int(cx), int(sh_top + s * 0.045))
    tree_l = (int(cx - s * 0.055), int(sh_top + s * 0.25))
    tree_r = (int(cx + s * 0.055), int(sh_top + s * 0.25))
    line_c = (29, 78, 216, 235)      # 蓝
    lw = max(1, s // 48)
    d.line([tree_c, tree_u], fill=line_c, width=lw)
    d.line([tree_c, tree_l], fill=line_c, width=lw)
    d.line([tree_c, tree_r], fill=line_c, width=lw)
    for (nx, ny) in (tree_u, tree_l, tree_r):
        d.ellipse([nx - node_r, ny - node_r, nx + node_r, ny + node_r], fill=(37, 99, 235, 255))
    # 中心节点更大更亮
    d.ellipse([tree_c[0] - node_r * 1.4, tree_c[1] - node_r * 1.4,
               tree_c[0] + node_r * 1.4, tree_c[1] + node_r * 1.4],
              fill=(29, 78, 216, 255), outline=(255, 255, 255, 200), width=lw)

    # 5. 右下角绿色「在线」状态点（带白描边）
    dot = (int(s * 0.80), int(s * 0.80))
    dot_r = s * 0.055
    d.ellipse([dot[0] - dot_r, dot[1] - dot_r, dot[0] + dot_r, dot[1] + dot_r],
              fill=(34, 197, 94, 255), outline=(255, 255, 255, 255), width=max(1, s // 40))

    return img


if __name__ == '__main__':
    sizes = [256, 128, 64, 48, 32, 24, 16]
    base = make(SIZE)
    imgs = [base.resize((s, s), Image.LANCZOS) for s in sizes]
    imgs[0].save(OUT, format='ICO', sizes=[(s, s) for s in sizes], append_images=imgs[1:])
    print('written', OUT, os.path.getsize(OUT), 'bytes')
