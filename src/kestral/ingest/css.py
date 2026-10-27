"""Decide from CSS whether a person viewing a page would see an element.

The extractor uses this to find text that is in the markup but not on the
screen. It reads inline ``style`` attributes and ``<style>`` blocks and works
out, for each element, the declarations that win the cascade (specificity,
``!important``, source order, custom properties). It models the ways text is
hidden in practice: not displayed, invisible, transparent, too small to read,
clipped, moved off the page, or drawn in the colour of its background.

Two rules keep it from hiding text a reader does see:

* A selector is used only when it can be evaluated exactly. Selectors with
  pseudo-elements, ``:not()``, ``:has()``, interaction states (``:hover``) or
  other features that cannot be decided from the markup are ignored, since
  guessing would hide the wrong elements.
* Low contrast is certain only when both colours are known. A page that links
  external stylesheets, which Kestral does not fetch, may set colours this
  module cannot see; the extractor then reports such text as doubtful rather
  than hidden.

Media queries are evaluated for two screens, a phone (390 px wide) and a
desktop (1440 px wide), with a light colour scheme and no reduced motion. The
extractor treats text as hidden only when it is hidden on both, so the
mobile and desktop copies of a responsive page are both kept. Rules for print
never apply.

Matching does a bounded amount of work per document. A stylesheet that would
need more raises :class:`TooComplex`, so a crafted page cannot hold a worker
for minutes. Standard library only.
"""

from __future__ import annotations

import colorsys
import math
import re
import time
from dataclasses import dataclass, field
from typing import Literal

Colour = tuple[float, float, float, float]  # r, g, b in 0-255, alpha in 0-1

WHITE: Colour = (255.0, 255.0, 255.0, 1.0)
BLACK: Colour = (0.0, 0.0, 0.0, 1.0)
# A background image: what lies behind the text is unknown.
UNKNOWN: Colour = (-1.0, -1.0, -1.0, 1.0)

# Text whose luminance is this close to its background cannot be read.
_MIN_CONTRAST = 0.08
# Below these sizes text cannot be read.
_MIN_FONT = {"px": 3.0, "pt": 2.25, "em": 0.2, "rem": 0.2, "%": 20.0, "": 3.0}
# Moved this far out of view (in px) the text is off the page. Margins and
# transforms are used for layout, so they need a larger offset.
_OFF_SCREEN = 100.0
_OFF_SCREEN_FAR = 1000.0
_TO_PX = {
    "px": 1.0, "": 1.0, "pt": 4 / 3, "pc": 16.0, "in": 96.0, "cm": 37.8, "mm": 3.78,
    "q": 0.945, "em": 16.0, "rem": 16.0,
}  # fmt: skip
# Numbers are matched without overlapping alternatives (no "\d*\.?\d+"), so a
# long run of digits cannot make the match backtrack, and in ASCII only:
# float() would also accept "1_0" and Arabic-Indic digits, which CSS does not.
_NUMBER = r"[-+]?(?:[0-9]+(?:\.[0-9]*)?|\.[0-9]+)(?:e[-+]?[0-9]+)?"
_LENGTH = re.compile(rf"^({_NUMBER})\s*([a-z%]*)$", re.I | re.A)
# A value longer than this is not a length, colour or keyword this module
# reads; it is cut before any pattern sees it.
MAX_VALUE_CHARS = 512
MAX_CUSTOM_PROPERTIES = 4096
# Wall-clock limit on stylesheet work for one document, in seconds.
MAX_CSS_SECONDS = 10.0

# Limits on what one document may ask for. Real pages stay far below them.
MAX_RULES = 200_000
MAX_SELECTOR_CHARS = 4_000
MAX_COMPOUNDS = 16
MAX_NESTING = 32
MAX_VAR_DEPTH = 8
# A selector that expands into more alternatives than this (":is()" lists,
# nested rules under many parents) is refused as too complex, never cut short.
MAX_ALTERNATIVES = 256
# Units of matching work per document (one unit is one compound tested
# against one element). Large real pages need well under a tenth of this.
MAX_WORK = 3_000_000

# Hiding the page root hides everything, which is how anti-flicker and
# anti-clickjacking snippets work until a script reveals the page. That says
# nothing about one part of the page, so only colours are taken from such rules.
ROOT_TAGS = frozenset({"html", "body", "head"})
# The tag of the document node above the top element; no selector matches it.
ROOT = "#document"

# The properties this module reads; everything else is dropped on parsing.
_COLOUR_PROPS = frozenset(
    {
        "color", "background", "background-color", "background-image", "background-clip",
        "-webkit-background-clip", "-webkit-text-fill-color",
    }
)  # fmt: skip
_LAYOUT_PROPS = frozenset(
    {
        "display", "visibility", "content-visibility", "opacity", "filter", "font-size",
        "transform", "translate", "scale", "height", "width", "max-height", "max-width",
        "overflow", "overflow-x", "overflow-y", "padding", "padding-top", "padding-bottom",
        "padding-left", "padding-right", "clip", "clip-path", "left", "top", "right",
        "bottom", "text-indent", "margin-left", "margin-top",
    }
)  # fmt: skip
_RELEVANT = _COLOUR_PROPS | _LAYOUT_PROPS

# Pseudo-classes that only narrow which elements match, in ways that do not
# matter for whether text is shown. Treating them as always true can only
# make a rule match more of the elements its other parts select.
_IGNORABLE = frozenset({"lang", "dir", "link", "any-link", "scope"})
# Pseudo-classes decided by an element's position among the siblings before
# it, which is known when the element opens. Those that depend on later
# siblings (:last-child, :only-child, :nth-last-*) are not.
_POSITIONAL = {
    "first-child": ("child", "0n+1"), "first-of-type": ("type", "0n+1"),
    "nth-child": ("child", None), "nth-of-type": ("type", None),
}  # fmt: skip

# The two screens media queries are evaluated for: (width, height) in px.
PROFILES = ("narrow", "wide")
ALL_PROFILES = frozenset(PROFILES)
_VIEWPORTS = {"narrow": (390.0, 844.0), "wide": (1440.0, 900.0)}
_EXPANDING = frozenset({"is", "where", "matches", "-webkit-any", "-moz-any"})
# States an element is not in when the page loads; a rule needing one hides
# nothing a reader sees on arrival.
_STATES = frozenset(
    {
        "hover", "focus", "focus-within", "focus-visible", "active", "visited", "target",
        "target-within", "checked", "indeterminate", "user-invalid", "user-valid",
        "autofill", "-webkit-autofill", "playing", "paused", "fullscreen", "modal",
        "picture-in-picture", "popover-open", "open", "drag", "-moz-drag-over",
    }
)  # fmt: skip
# States every element is in on a working page (custom elements are defined
# once their script runs).
_ALWAYS = frozenset({"defined"})

# fmt: off
_NAMED: dict[str, tuple[int, int, int]] = {
    "aliceblue": (240, 248, 255), "antiquewhite": (250, 235, 215), "aqua": (0, 255, 255),
    "aquamarine": (127, 255, 212), "azure": (240, 255, 255), "beige": (245, 245, 220),
    "bisque": (255, 228, 196), "black": (0, 0, 0), "blanchedalmond": (255, 235, 205),
    "blue": (0, 0, 255), "blueviolet": (138, 43, 226), "brown": (165, 42, 42),
    "burlywood": (222, 184, 135), "cadetblue": (95, 158, 160), "chartreuse": (127, 255, 0),
    "chocolate": (210, 105, 30), "coral": (255, 127, 80), "cornflowerblue": (100, 149, 237),
    "cornsilk": (255, 248, 220), "crimson": (220, 20, 60), "cyan": (0, 255, 255),
    "darkblue": (0, 0, 139), "darkcyan": (0, 139, 139), "darkgoldenrod": (184, 134, 11),
    "darkgray": (169, 169, 169), "darkgreen": (0, 100, 0), "darkgrey": (169, 169, 169),
    "darkkhaki": (189, 183, 107), "darkmagenta": (139, 0, 139),
    "darkolivegreen": (85, 107, 47), "darkorange": (255, 140, 0), "darkorchid": (153, 50, 204),
    "darkred": (139, 0, 0), "darksalmon": (233, 150, 122), "darkseagreen": (143, 188, 143),
    "darkslateblue": (72, 61, 139), "darkslategray": (47, 79, 79),
    "darkslategrey": (47, 79, 79), "darkturquoise": (0, 206, 209),
    "darkviolet": (148, 0, 211), "deeppink": (255, 20, 147), "deepskyblue": (0, 191, 255),
    "dimgray": (105, 105, 105), "dimgrey": (105, 105, 105), "dodgerblue": (30, 144, 255),
    "firebrick": (178, 34, 34), "floralwhite": (255, 250, 240), "forestgreen": (34, 139, 34),
    "fuchsia": (255, 0, 255), "gainsboro": (220, 220, 220), "ghostwhite": (248, 248, 255),
    "gold": (255, 215, 0), "goldenrod": (218, 165, 32), "gray": (128, 128, 128),
    "green": (0, 128, 0), "greenyellow": (173, 255, 47), "grey": (128, 128, 128),
    "honeydew": (240, 255, 240), "hotpink": (255, 105, 180), "indianred": (205, 92, 92),
    "indigo": (75, 0, 130), "ivory": (255, 255, 240), "khaki": (240, 230, 140),
    "lavender": (230, 230, 250), "lavenderblush": (255, 240, 245), "lawngreen": (124, 252, 0),
    "lemonchiffon": (255, 250, 205), "lightblue": (173, 216, 230), "lightcoral": (240, 128, 128),
    "lightcyan": (224, 255, 255), "lightgoldenrodyellow": (250, 250, 210),
    "lightgray": (211, 211, 211), "lightgreen": (144, 238, 144), "lightgrey": (211, 211, 211),
    "lightpink": (255, 182, 193), "lightsalmon": (255, 160, 122),
    "lightseagreen": (32, 178, 170), "lightskyblue": (135, 206, 250),
    "lightslategray": (119, 136, 153), "lightslategrey": (119, 136, 153),
    "lightsteelblue": (176, 196, 222), "lightyellow": (255, 255, 224), "lime": (0, 255, 0),
    "limegreen": (50, 205, 50), "linen": (250, 240, 230), "magenta": (255, 0, 255),
    "maroon": (128, 0, 0), "mediumaquamarine": (102, 205, 170), "mediumblue": (0, 0, 205),
    "mediumorchid": (186, 85, 211), "mediumpurple": (147, 112, 219),
    "mediumseagreen": (60, 179, 113), "mediumslateblue": (123, 104, 238),
    "mediumspringgreen": (0, 250, 154), "mediumturquoise": (72, 209, 204),
    "mediumvioletred": (199, 21, 133), "midnightblue": (25, 25, 112),
    "mintcream": (245, 255, 250), "mistyrose": (255, 228, 225), "moccasin": (255, 228, 181),
    "navajowhite": (255, 222, 173), "navy": (0, 0, 128), "oldlace": (253, 245, 230),
    "olive": (128, 128, 0), "olivedrab": (107, 142, 35), "orange": (255, 165, 0),
    "orangered": (255, 69, 0), "orchid": (218, 112, 214), "palegoldenrod": (238, 232, 170),
    "palegreen": (152, 251, 152), "paleturquoise": (175, 238, 238),
    "palevioletred": (219, 112, 147), "papayawhip": (255, 239, 213),
    "peachpuff": (255, 218, 185), "peru": (205, 133, 63), "pink": (255, 192, 203),
    "plum": (221, 160, 221), "powderblue": (176, 224, 230), "purple": (128, 0, 128),
    "rebeccapurple": (102, 51, 153), "red": (255, 0, 0), "rosybrown": (188, 143, 143),
    "royalblue": (65, 105, 225), "saddlebrown": (139, 69, 19), "salmon": (250, 128, 114),
    "sandybrown": (244, 164, 96), "seagreen": (46, 139, 87), "seashell": (255, 245, 238),
    "sienna": (160, 82, 45), "silver": (192, 192, 192), "skyblue": (135, 206, 235),
    "slateblue": (106, 90, 205), "slategray": (112, 128, 144), "slategrey": (112, 128, 144),
    "snow": (255, 250, 250), "springgreen": (0, 255, 127), "steelblue": (70, 130, 180),
    "tan": (210, 180, 140), "teal": (0, 128, 128), "thistle": (216, 191, 216),
    "tomato": (255, 99, 71), "turquoise": (64, 224, 208), "violet": (238, 130, 238),
    "wheat": (245, 222, 179), "white": (255, 255, 255), "whitesmoke": (245, 245, 245),
    "yellow": (255, 255, 0), "yellowgreen": (154, 205, 50),
}
# fmt: on


class TooComplex(Exception):  # noqa: N818
    """The stylesheets would need more work than one document may use."""


class Budget:
    """Counts the stylesheet work for one document, and its time."""

    def __init__(self, limit: int = MAX_WORK, seconds: float = MAX_CSS_SECONDS) -> None:
        self.limit = limit
        self.used = 0
        self._deadline = time.perf_counter() + seconds
        self._next_check = 4096

    def spend(self, units: int = 1) -> None:
        self.used += units
        if self.used > self.limit:
            raise TooComplex
        if self.used >= self._next_check:
            self._next_check = self.used + 4096
            if time.perf_counter() > self._deadline:
                raise TooComplex


# ---- values --------------------------------------------------------------

Declarations = dict[str, tuple[str, bool]]  # property -> (value, important)


def declarations(style: str) -> Declarations:
    """Parse ``a: b; c: d`` into {property: (value, important)}.

    Only the properties this module reads, and custom properties, are kept;
    values are lower case except for custom properties. A later declaration
    wins over an earlier one unless only the earlier one is ``!important``.
    """
    out: Declarations = {}
    for part in style.split(";"):
        name, sep, value = part.partition(":")
        if not sep:
            continue
        name = name.strip().lower()
        custom = name.startswith("--")
        if not custom and name not in _RELEVANT:
            continue
        value = value.strip()[:MAX_VALUE_CHARS]
        important = bool(re.search(r"!\s*important\s*$", value, re.I))
        if important:
            value = re.sub(r"!\s*important\s*$", "", value, flags=re.I).strip()
        if not value:
            continue
        if not custom:
            value = value.lower()
        if name in out and out[name][1] and not important:
            continue
        out[name] = (value, important)
    return out


_VAR = re.compile(r"var\(\s*(--[\w-]+)\s*(?:,\s*((?:[^()]|\([^()]*\))*))?\)")


def resolve(value: str, variables: dict[str, str]) -> tuple[str, bool]:
    """Substitute ``var(--name, fallback)`` from the custom properties in effect.

    Returns the value and whether any variable was missing (its fallback, if
    any, was used): the page may define it in a stylesheet Kestral cannot see.
    """
    missing = False
    for _ in range(MAX_VAR_DEPTH):
        match = _VAR.search(value) if "var(" in value else None
        if not match:
            break
        replacement = variables.get(match.group(1))
        if replacement is None:
            missing = True
            replacement = (match.group(2) or "").strip()
        value = value[: match.start()] + replacement + value[match.end() :]
    return value.lower(), missing


def _number(value: str) -> tuple[float, str] | None:
    match = _LENGTH.match(value.strip())
    if not match:
        return None
    try:
        number = float(match.group(1))
    except ValueError:
        return None
    if not math.isfinite(number):
        return None
    return number, match.group(2).lower()


def _px(value: str) -> float | None:
    """A length in px, for the units that do not depend on the layout."""
    parsed = _number(value)
    if parsed is None or parsed[1] not in _TO_PX:
        return None
    return parsed[0] * _TO_PX[parsed[1]]


def _channel(token: str, top: float) -> float:
    token = token.strip()
    number = token[:-1] if token.endswith("%") else token
    if not re.fullmatch(_NUMBER, number, re.A | re.I):
        raise ValueError(token)
    value = float(number) * top / 100 if token.endswith("%") else float(number)
    if not math.isfinite(value):
        raise ValueError(token)
    return max(0.0, min(top, value))


def _hue(token: str) -> float:
    match = re.fullmatch(rf"({_NUMBER})(deg|turn|rad|grad)?", token.strip(), re.A)
    if not match:
        raise ValueError(token)
    number = float(match.group(1))
    if not math.isfinite(number):
        raise ValueError(token)
    scale = {"turn": 360.0, "rad": 180 / math.pi, "grad": 0.9}.get(match.group(2) or "", 1.0)
    return (number * scale) % 360 / 360


def colour(value: str) -> Colour | None:
    """Parse a CSS colour, or None for a value this module does not understand."""
    value = value.strip().lower()
    if value == "transparent":
        return (0.0, 0.0, 0.0, 0.0)
    if value in _NAMED:
        red, green, blue = _NAMED[value]
        return (float(red), float(green), float(blue), 1.0)
    if value.startswith("#"):
        digits = value[1:]
        if len(digits) in (3, 4):
            digits = "".join(c * 2 for c in digits)
        if len(digits) not in (6, 8) or not re.fullmatch(r"[0-9a-f]+", digits):
            return None
        channels = [int(digits[i : i + 2], 16) for i in range(0, len(digits), 2)]
        alpha = channels[3] / 255 if len(channels) == 4 else 1.0
        return (float(channels[0]), float(channels[1]), float(channels[2]), alpha)
    lab = re.fullmatch(r"(ok)?(?:lab|lch)\(\s*([0-9.]+)(%?)[\s,/][^()]*\)", value)
    if lab:
        # Lightness only, as a grey: enough to judge contrast.
        try:
            light = float(lab.group(2))
        except ValueError:
            return None
        scale = 1.0 if lab.group(1) and not lab.group(3) else 100.0
        grey = max(0.0, min(1.0, light / scale)) * 255
        stated = re.search(r"/\s*([0-9]+(?:\.[0-9]*)?)(%?)\s*\)$", value)
        opacity = float(stated.group(1)) / (100 if stated.group(2) else 1) if stated else 1.0
        return (grey, grey, grey, min(1.0, opacity))
    match = re.fullmatch(r"(rgba?|hsla?)\(([^()]*)\)", value)
    if not match:
        return None
    parts = [p for p in re.split(r"[\s,/]+", match.group(2).strip()) if p]
    if len(parts) not in (3, 4):
        return None
    try:
        alpha = _channel(parts[3], 1.0) if len(parts) == 4 else 1.0
        if match.group(1).startswith("rgb"):
            r, g, b = (_channel(p, 255) for p in parts[:3])
        else:
            light, sat = _channel(parts[2], 1.0), _channel(parts[1], 1.0)
            r, g, b = (c * 255 for c in colorsys.hls_to_rgb(_hue(parts[0]), light, sat))
    except ValueError:
        return None
    return (r, g, b, alpha)


def luminance(c: Colour) -> float:
    return (0.2126 * c[0] + 0.7152 * c[1] + 0.0722 * c[2]) / 255


_COLOUR_TOKEN = re.compile(r"#[0-9a-f]{3,8}\b|(?:rgba?|hsla?)\([^()]*\)|\b[a-z]+\b")


def background_colour(decl: dict[str, str]) -> Colour | None:
    """The background a declaration block sets, UNKNOWN for an image, or None."""
    image = decl.get("background-image", "") + " " + decl.get("background", "")
    if "url(" in image or "image-set(" in image or "element(" in image:
        return UNKNOWN
    if "gradient(" in image:
        # A gradient is judged by its stops: if they are all alike, that is
        # the colour behind the text; otherwise it is unknown.
        stops = [c for c in map(colour, _COLOUR_TOKEN.findall(image)) if c is not None]
        opaque = [s for s in stops if s[3] > 0.5]
        if opaque and max(map(luminance, opaque)) - min(map(luminance, opaque)) < _MIN_CONTRAST:
            return opaque[0]
        return UNKNOWN
    if "background-color" in decl:
        return colour(decl["background-color"])
    if "background" in decl:
        for token in _COLOUR_TOKEN.findall(decl["background"]):
            parsed = colour(token)
            if parsed is not None:
                return parsed
    return None


def contrast_too_low(text: Colour, background: Colour) -> bool:
    """True when text in this colour cannot be read on this background."""
    if text[3] <= 0.05:
        return True
    if background == UNKNOWN:
        return False
    return abs(luminance(text) - luminance(background)) < _MIN_CONTRAST


def _clipped(decl: dict[str, str]) -> bool:
    clip = decl.get("clip", "")
    if clip.startswith("rect("):
        sizes = [_px(v) for v in re.split(r"[\s,]+", clip[5:].rstrip(")").strip()) if v]
        if len(sizes) == 4 and all(s is not None for s in sizes):
            top, right, bottom, left = (s or 0.0 for s in sizes)
            if right - left <= 1 or bottom - top <= 1:
                return True
    path = decl.get("clip-path", "")
    inset = re.match(r"inset\(\s*([0-9]+(?:\.[0-9]*)?|\.[0-9]+)%", path)
    if inset and float(inset.group(1)) >= 50:
        return True
    return bool(re.match(r"(?:circle|ellipse)\(\s*0(?:px|%)?[\s)]", path))


def _padding_px(value: str) -> float:
    """A padding in px; a percentage (of the width) counts as ample."""
    parsed = _number(value)
    if parsed is not None and parsed[1] == "%":
        return 100.0 if parsed[0] > 0 else 0.0
    return max(0.0, _px(value) or 0.0)


def _padding(decl: dict[str, str], sides: tuple[str, str]) -> float:
    total = sum(_padding_px(decl.get("padding-" + side, "0")) for side in sides)
    shorthand = decl.get("padding", "").split()
    if shorthand:
        total += max(_padding_px(v) for v in shorthand)
    return total


def _no_room(decl: dict[str, str]) -> bool:
    """A box too small for its text, with the overflow cut off."""
    cut = any(decl.get(p) in ("hidden", "clip") for p in ("overflow", "overflow-x", "overflow-y"))
    if not cut:
        return False  # text that does not fit is drawn outside the box
    for prop, sides in (
        ("height", ("top", "bottom")),
        ("max-height", ("top", "bottom")),
        ("width", ("left", "right")),
        ("max-width", ("left", "right")),
    ):
        size = _px(decl[prop]) if prop in decl else None
        # Zero height with padding is the aspect-ratio idiom: the box is not empty.
        if size is not None and size <= 1 and _padding(decl, sides) <= 1:
            return True
    return False


def _shifts(value: str) -> list[float]:
    """The pixel offsets in a transform or translate value."""
    args = re.findall(r"translate(?:3d|x|y|z)?\(([^()]*)\)", value)
    if value and "(" not in value:
        args.append(value)
    out: list[float] = []
    for arg in args:
        for token in re.split(r"[\s,]+", arg.strip()):
            px = _px(token) if token else None
            if px is not None:
                out.append(px)
    return out


def layout_reason(decl: dict[str, str]) -> str | None:
    """Why an element with these declarations is not on screen, colour aside."""
    if not decl:
        return None
    if decl.get("display") == "none" or decl.get("content-visibility") == "hidden":
        return "css_display_none"
    if decl.get("visibility") in ("hidden", "collapse"):
        return "css_visibility_hidden"
    opacity = _number(decl.get("opacity", "1"))
    if opacity is not None:
        value = opacity[0] / 100 if opacity[1] == "%" else opacity[0]
        if value <= 0.05:
            return "css_opacity_zero"
    if re.search(r"opacity\(\s*0*(?:\.0+)?%?\s*\)", decl.get("filter", "")):
        return "css_opacity_zero"
    size = _number(decl["font-size"]) if "font-size" in decl else None
    if size is not None and size[1] in _MIN_FONT and size[0] < _MIN_FONT[size[1]]:
        return "css_zero_size"
    transform = decl.get("transform", "")
    scales = re.findall(r"scale(?:3d|x|y)?\(\s*([0-9.]+)", transform) + re.findall(
        r"^\s*([0-9.]+)", decl.get("scale", "")
    )
    if any(_number(v) is not None and (_number(v) or (1.0, ""))[0] <= 0.05 for v in scales):
        return "css_zero_size"
    if _no_room(decl):
        return "css_zero_size"
    if _clipped(decl):
        return "css_clipped"
    for prop in ("left", "top", "right", "bottom", "text-indent"):
        offset = _px(decl[prop]) if prop in decl else None
        if offset is not None and offset <= -_OFF_SCREEN:
            return "css_off_screen"
    for prop in ("margin-left", "margin-top"):
        offset = _px(decl[prop]) if prop in decl else None
        if offset is not None and offset <= -_OFF_SCREEN_FAR:
            return "css_off_screen"
    shifts = _shifts(transform) + _shifts(decl.get("translate", ""))
    if any(s <= -_OFF_SCREEN_FAR for s in shifts):
        return "css_off_screen"
    return None


# ---- selectors -----------------------------------------------------------


@dataclass(eq=False, slots=True)
class Element:
    """What a selector can test about an element, and where it sits."""

    tag: str
    id: str = ""
    classes: frozenset[str] = frozenset()
    attrs: dict[str, str] = field(default_factory=dict)
    parent: Element | None = None
    # The element's position among its parent's element children, and among
    # those with its tag.
    index: int = 0
    type_index: int = 0
    children: list[Element] = field(default_factory=list)
    type_counts: dict[str, int] = field(default_factory=dict)
    memo: dict[int, bool] = field(default_factory=dict)

    def lookup_keys(self) -> list[str]:
        keys = [self.tag, "*", *("." + c for c in self.classes), *("[" + a for a in self.attrs)]
        if self.id:
            keys.append("#" + self.id)
        return keys

    def previous(self) -> Element | None:
        if self.parent is None or self.index == 0:
            return None
        return self.parent.children[self.index - 1]


_AttrTest = tuple[str, "str | None", str]


_NthTest = tuple[str, int, int]  # ("child" or "type", a, b): position = a*n + b


def _nth(argument: str) -> tuple[int, int] | None:
    """Parse the argument of :nth-child() into (a, b), or None."""
    arg = re.sub(r"\s+", "", argument.lower())
    if arg == "odd":
        return 2, 1
    if arg == "even":
        return 2, 0
    match = re.fullmatch(r"([-+]?[0-9]*)n([-+][0-9]+)?|([-+]?[0-9]+)", arg)
    if not match:
        return None
    if match.group(3) is not None:
        return 0, int(match.group(3))
    a = match.group(1)
    step = 1 if a in ("", "+") else -1 if a == "-" else int(a)
    return step, int(match.group(2) or 0)


def _position_matches(position: int, a: int, b: int) -> bool:
    """Is ``position`` (1-based) equal to a*n + b for some n >= 0?"""
    if a == 0:
        return position == b
    n, rest = divmod(position - b, a)
    return rest == 0 and n >= 0


@dataclass(frozen=True)
class _Compound:
    tag: str | None
    id: str | None
    classes: tuple[str, ...]
    attrs: tuple[_AttrTest, ...]
    nth: tuple[_NthTest, ...] = ()
    # :not() arguments: the element must match none of them.
    negations: tuple[_Compound, ...] = ()

    def key(self) -> str:
        if self.id:
            return "#" + self.id
        if self.classes:
            return "." + self.classes[0]
        if self.tag:
            return self.tag
        if self.attrs:
            return "[" + self.attrs[0][0]
        return "*"

    def matches(self, el: Element) -> bool:
        if el.tag == ROOT:
            return False
        if self.tag and self.tag != el.tag:
            return False
        if self.id and self.id != el.id:
            return False
        if any(c not in el.classes for c in self.classes):
            return False
        for name, op, value in self.attrs:
            have = el.attrs.get(name)
            if have is None:
                return False
            if op is None:
                continue
            ok = {
                "=": have == value,
                "~=": value in have.split(),
                "^=": bool(value) and have.startswith(value),
                "$=": bool(value) and have.endswith(value),
                "*=": bool(value) and value in have,
                "|=": have == value or have.startswith(value + "-"),
            }.get(op, False)
            if not ok:
                return False
        for kind, a, b in self.nth:
            position = (el.index if kind == "child" else el.type_index) + 1
            if not _position_matches(position, a, b):
                return False
        return not any(negation.matches(el) for negation in self.negations)


Combinator = Literal[" ", ">", "+", "~"]
Specificity = tuple[int, int, int]


@dataclass(frozen=True)
class Selector:
    """A complex selector: compounds joined by combinators, left to right."""

    compounds: tuple[_Compound, ...]
    combinators: tuple[Combinator, ...]  # combinators[i] joins compounds[i] and [i + 1]
    specificity: Specificity


def _split_top(text: str, separators: str) -> list[tuple[str, str]]:
    """Split at separator characters outside brackets, parentheses and quotes.

    Returns (piece, the separator that ended it) pairs.
    """
    out: list[tuple[str, str]] = []
    depth = 0
    quote = ""
    start = 0
    for i, char in enumerate(text):
        if quote:
            if char == quote:
                quote = ""
        elif char in "\"'":
            quote = char
        elif char in "([":
            depth += 1
        elif char in ")]":
            depth = max(0, depth - 1)
        elif depth == 0 and char in separators:
            out.append((text[start:i], char))
            start = i + 1
    out.append((text[start:], ""))
    return out


_TOKEN = re.compile(
    r"\*|[\w-]+|#[\w-]+|\.[\w-]+|\[(?:[^\]\"']|\"[^\"]*\"|'[^']*')*\]"
    r"|::?[\w-]+(?:\((?:[^()]|\([^()]*\))*\))?"
)
_ATTR = re.compile(
    r"""\[\s*([\w:-]+)\s*(?:([~^$*|]?=)\s*(?:"([^"]*)"|'([^']*)'|([^\s\]"']*))\s*[is]?\s*)?\]"""
)


def _add(a: Specificity, b: Specificity) -> Specificity:
    return (a[0] + b[0], a[1] + b[1], a[2] + b[2])


def _compounds(text: str) -> list[tuple[_Compound, Specificity]] | None:
    """Parse one compound selector into its alternatives (``:is()`` expands).

    Returns None when the compound cannot be evaluated exactly.
    """
    tag: str | None = None
    ident: str | None = None
    classes: list[str] = []
    attrs: list[_AttrTest] = []
    nth: list[_NthTest] = []
    negations: list[_Compound] = []
    undecided = False  # a pseudo-class whose answer is not known here
    never = False  # a pseudo-class no element has when the page loads
    ids = cls = tags = 0
    expansions: list[list[tuple[_Compound, Specificity]]] = []
    pos = 0
    for match in _TOKEN.finditer(text):
        if match.start() != pos:
            return None
        token = match.group(0)
        pos = match.end()
        if token.startswith("::"):
            return None  # a pseudo-element: the rule styles generated content
        if token.startswith(":"):
            name = re.match(r":([\w-]+)", token)
            pseudo = name.group(1).lower() if name else ""
            if pseudo == "root":
                if tag not in (None, "html"):
                    return None
                tag = "html"
                tags += 1
            elif pseudo in _IGNORABLE:
                cls += 1
            elif pseudo in _POSITIONAL:
                kind, fixed = _POSITIONAL[pseudo]
                argument = fixed or (token[token.index("(") + 1 : -1] if "(" in token else "")
                parsed_nth = _nth(argument)
                if parsed_nth is None:
                    return None  # includes the "of S" form
                nth.append((kind, *parsed_nth))
                cls += 1
            elif pseudo in _EXPANDING and "(" in token:
                # Forgiving: an alternative that cannot match on arrival is
                # dropped, the others kept.
                options: list[tuple[_Compound, Specificity]] = []
                for piece, _ in _split_top(token[token.index("(") + 1 : -1], ","):
                    parsed = _compounds(piece.strip()) if piece.strip() else None
                    options.extend(parsed or [])
                if not options:
                    never = True
                expansions.append(options)
            elif pseudo == "not" and "(" in token:
                inner: list[_Compound] = []
                for piece, _ in _split_top(token[token.index("(") + 1 : -1], ","):
                    parsed = _compounds(piece.strip()) if piece.strip() else None
                    if parsed is None:
                        undecided = True
                        continue
                    inner.extend(compound for compound, _ in parsed)
                negations.extend(inner)
                cls += 1
            elif pseudo in _STATES:
                never = True
            elif pseudo in _ALWAYS:
                pass
            else:
                # :has(), :empty, :last-child and the like cannot be decided
                # when the element opens.
                undecided = True
        elif token.startswith("#"):
            ident = token[1:]
            ids += 1
        elif token.startswith("."):
            classes.append(token[1:])
            cls += 1
        elif token.startswith("["):
            attr = _ATTR.fullmatch(token)
            if not attr:
                return None
            value = next((g for g in attr.group(3, 4, 5) if g is not None), "")
            attrs.append((attr.group(1).lower(), attr.group(2), value))
            cls += 1
        elif token != "*":
            if tag is not None or match.start() != 0:
                return None  # a type selector comes first, once
            tag = token.lower()
            tags += 1
    if not text or pos != len(text) or never:
        return None
    if undecided and not (ident or classes or attrs):
        # Without a class, id or attribute the rule would reach every element
        # of a type ("div:has(...)"): ignore it. With one, it reaches only
        # elements the page marked, so it is applied as if the undecided
        # part held: hiding too much of marked text is the safe side.
        return None
    results = [
        (
            _Compound(tag, ident, tuple(classes), tuple(attrs), tuple(nth), tuple(negations)),
            (ids, cls, tags),
        )
    ]
    for options in expansions:
        merged: list[tuple[_Compound, Specificity]] = []
        for current, spec in results:
            for option, extra in options:
                if current.tag and option.tag and current.tag != option.tag:
                    continue
                if current.id and option.id and current.id != option.id:
                    continue
                combined = _Compound(
                    current.tag or option.tag,
                    current.id or option.id,
                    current.classes + option.classes,
                    current.attrs + option.attrs,
                    current.nth + option.nth,
                    current.negations + option.negations,
                )
                merged.append((combined, _add(spec, extra)))
        if len(merged) > MAX_ALTERNATIVES:
            raise TooComplex
        results = merged
    if not results:
        return None
    return results


def parse_selector(text: str) -> list[Selector]:
    """Parse one complex selector into its alternatives.

    Returns [] when it cannot be evaluated exactly.
    """
    text = text.strip()
    if not text:
        return []
    if len(text) > MAX_SELECTOR_CHARS:
        raise TooComplex  # never skipped silently: that would let it hide text
    parts: list[str] = []
    combinators: list[Combinator] = []
    pending: str | None = None
    for piece, separator in _split_top(text, " \t\n>+~"):
        if piece:
            if parts:
                combinators.append(pending or " ")  # type: ignore[arg-type]
            parts.append(piece)
            pending = None
        if separator in (">", "+", "~"):
            if not parts or pending in (">", "+", "~"):
                return []
            pending = separator
        elif separator and pending is None and parts:
            pending = " "
    if not parts or pending not in (None, " "):
        return []
    if len(parts) > MAX_COMPOUNDS:
        raise TooComplex
    options: list[tuple[tuple[_Compound, ...], Specificity]] = [((), (0, 0, 0))]
    for part in parts:
        parsed = _compounds(part)
        if parsed is None:
            return []
        options = [
            ((*chain, compound), _add(spec, extra))
            for chain, spec in options
            for compound, extra in parsed
        ]
        if len(options) > MAX_ALTERNATIVES:
            raise TooComplex
    return [Selector(chain, tuple(combinators), spec) for chain, spec in options]


# ---- stylesheets ---------------------------------------------------------


@dataclass(frozen=True)
class Rule:
    """A stylesheet rule this module can use."""

    selector: Selector
    declarations: Declarations
    order: int
    # The screens the rule applies on (see PROFILES).
    media: frozenset[str] = ALL_PROFILES
    # Declared inside @layer: beaten by unlayered rules (the other way round
    # for !important).
    layered: bool = False


def _compare(left: float, op: str, right: float) -> bool:
    return {
        "<": left < right,
        "<=": left <= right,
        ">": left > right,
        ">=": left >= right,
        "=": left == right,
    }[op]


def _feature(feature: str, profile: str) -> bool:
    """Does one media feature, such as ``min-width: 600px``, hold on a screen?

    Features this module does not know are taken to hold.
    """
    width, height = _VIEWPORTS[profile]
    feature = " ".join(feature.lower().split())
    if ":" not in feature:
        # Range syntax: (width >= 600px), (400px <= width < 900px).
        parts = re.split(r"\s*(<=|>=|<|>|=)\s*", feature)
        if len(parts) < 3:
            if feature in ("hover", "any-hover"):
                return profile == "wide"
            # Bare features: a colour screen is not monochrome and not a grid.
            return feature not in ("monochrome", "grid")
        values: list[float | None] = []
        for token in parts[0::2]:
            values.append(
                width if token == "width" else height if token == "height" else _px(token)
            )
        for i, op in enumerate(parts[1::2]):
            left, right = values[i], values[i + 1]
            if left is not None and right is not None and not _compare(left, op, right):
                return False
        return True
    name, value = (x.strip() for x in feature.split(":", 1))
    size = _px(value)
    for dimension, actual in (("width", width), ("height", height)):
        if size is not None and name in (dimension, "device-" + dimension):
            return actual == size
        if size is not None and name in ("min-" + dimension, "min-device-" + dimension):
            return actual >= size
        if size is not None and name in ("max-" + dimension, "max-device-" + dimension):
            return actual <= size
    if name == "orientation":
        return (value == "landscape") == (profile == "wide")
    if name in ("hover", "any-hover"):
        return (value == "hover") == (profile == "wide")
    if name in ("pointer", "any-pointer"):
        return {"fine": profile == "wide", "coarse": profile == "narrow", "none": False}.get(
            value, True
        )
    if name == "prefers-color-scheme":
        return value != "dark"
    if name in (
        "prefers-reduced-motion", "prefers-contrast", "prefers-reduced-transparency",
        "prefers-reduced-data", "forced-colors", "inverted-colors",
    ):  # fmt: skip
        return value in ("no-preference", "none")
    if name in ("monochrome", "grid"):
        return value in ("0", "")
    if name == "scripting":
        return value == "enabled"
    if name == "display-mode":
        return value == "browser"
    return True


def media_profiles(query: str) -> frozenset[str]:
    """The screens (see PROFILES) a media query list holds on."""
    query = " ".join(query.strip().lower().split())
    if not query:
        return ALL_PROFILES
    out: set[str] = set()
    for alternative, _ in _split_top(query, ","):
        alternative = alternative.strip()
        if not alternative:
            continue
        negated = alternative.startswith("not ")
        alternative = re.sub(r"^(?:not|only)\s+", "", alternative)
        features = re.findall(r"\(([^()]*)\)", alternative)
        words = [w for w in re.sub(r"\([^()]*\)", " ", alternative).split() if w != "and"]
        screen = not words or any(w in ("screen", "all") for w in words)
        for profile in PROFILES:
            holds = screen and all(_feature(f, profile) for f in features)
            if holds != negated:
                out.add(profile)
    return frozenset(out)


def media_applies(query: str) -> bool:
    """True when a media query list holds on at least one screen."""
    return bool(media_profiles(query))


Parsed = tuple[str, str, frozenset[str], bool]  # selectors, declarations, screens, layered


def parse_stylesheet(css: str, media: frozenset[str] = ALL_PROFILES) -> list[Parsed]:
    """(selector list, declarations, screens, layered) for every rule that
    applies on a screen; layered rules are those inside ``@layer``.

    Nested rules are flattened (``&`` is the parent selector). ``@media`` sets
    the screens a rule applies on; rules for no screen (print), and rules in
    at-rules that hold no element rules (``@font-face``, ``@keyframes`` ...),
    are skipped.
    """
    css = re.sub(r"/\*.*?(?:\*/|$)", "", css, flags=re.S)
    out: list[Parsed | None] = []
    length = len(css)

    def block(
        pos: int, parents: list[str] | None, screens: frozenset[str], layered: bool, depth: int
    ) -> tuple[int, str]:
        """Parse until the matching ``}``. Returns (position after it, own declarations)."""
        own: list[str] = []
        start = pos
        quote = ""
        while pos < length:
            char = css[pos]
            if quote:
                if char == quote or char == "\n":
                    quote = ""
            elif char in "\"'":
                quote = char
            elif (
                char in "uU"
                and css[pos : pos + 4].lower() == "url("
                and css[pos + 4 : pos + 5].lstrip()[:1] not in ("'", '"')
                and css[pos + 4 :].lstrip()[:1] not in ("'", '"')
            ):
                # An unquoted url() may hold "{", "}" or ";": skip to its end.
                # A quoted one is read as a string.
                end = css.find(")", pos)
                pos = length if end < 0 else end
            elif char == "{":
                prelude = css[start:pos].strip()
                if depth >= MAX_NESTING:
                    raise TooComplex
                if prelude.startswith("@"):
                    if re.match(r"@media\b", prelude, re.I):
                        inner_screens = screens & media_profiles(prelude[6:])
                    elif re.match(r"@(?:supports|layer|container|scope|document)\b", prelude, re.I):
                        inner_screens = screens
                    else:
                        inner_screens = frozenset()
                    inner_layered = layered or bool(re.match(r"@layer\b", prelude, re.I))
                    pos, inner = block(pos + 1, parents, inner_screens, inner_layered, depth + 1)
                    if parents is not None and inner_screens and inner.strip():
                        # Declarations directly inside a nested at-rule apply to the parent.
                        out.append((",".join(parents), inner, inner_screens, inner_layered))
                else:
                    selectors = [s.strip() for s, _ in _split_top(prelude, ",") if s.strip()]
                    if parents is not None:
                        selectors = [
                            s.replace("&", p) if "&" in s else f"{p} {s}"
                            for p in parents
                            for s in selectors
                        ]
                        if len(selectors) > MAX_ALTERNATIVES:
                            raise TooComplex
                    slot = len(out)
                    out.append(None)
                    pos, body = block(pos + 1, selectors, screens, layered, depth + 1)
                    if screens and selectors:
                        out[slot] = (",".join(selectors), body, screens, layered)
                start = pos
                continue
            elif char == "}":
                own.append(css[start:pos])
                return pos + 1, ";".join(own)
            elif char == ";":
                own.append(css[start:pos])
                start = pos + 1
            pos += 1
        own.append(css[start:pos])
        return pos, ";".join(own)

    pos = 0
    while pos < length:
        pos, _ = block(pos, None, media, False, 0)
    return [item for item in out if item is not None]


def stylesheet_rules(css: str, start: int = 0, media: frozenset[str] = ALL_PROFILES) -> list[Rule]:
    """The rules in a stylesheet that set a property this module reads."""
    rules: list[Rule] = []
    for selectors, body, screens, layered in parse_stylesheet(css, media):
        decl = declarations(body)
        if not decl:
            continue
        for text, _ in _split_top(selectors, ","):
            for selector in parse_selector(text):
                own = decl
                if selector.compounds[-1].tag in ROOT_TAGS:
                    own = {k: v for k, v in decl.items() if k not in _LAYOUT_PROPS}
                    if not own:
                        continue
                rules.append(Rule(selector, own, start + len(rules), screens, layered))
                if start + len(rules) > MAX_RULES:
                    raise TooComplex
    return rules


class RuleIndex:
    """Stylesheet rules looked up by the element they could select."""

    def __init__(self, rules: list[Rule], budget: Budget | None = None) -> None:
        self._rules = rules
        self.budget = budget or Budget()
        # Whether any rule applies on some screens only.
        self.by_screen = any(rule.media != ALL_PROFILES for rule in rules)
        self._by_key: dict[str, list[int]] = {}
        for index, rule in enumerate(rules):
            self._by_key.setdefault(rule.selector.compounds[-1].key(), []).append(index)

    def __bool__(self) -> bool:
        return bool(self._rules)

    def matching(self, el: Element) -> list[Rule]:
        """The rules that select ``el``, in source order."""
        found: set[int] = set()
        for key in el.lookup_keys():
            for index in self._by_key.get(key, ()):
                last = len(self._rules[index].selector.compounds) - 1
                if index not in found and self._full(el, index, last):
                    found.add(index)
        return [self._rules[i] for i in sorted(found)]

    def _full(self, el: Element, rule: int, k: int) -> bool:
        """Does ``el`` match compound ``k`` of the rule, with everything left of it?"""
        self.budget.spend()
        selector = self._rules[rule].selector
        if not selector.compounds[k].matches(el):
            return False
        if k == 0:
            return True
        combinator = selector.combinators[k - 1]
        if combinator == ">":
            return el.parent is not None and self._full(el.parent, rule, k - 1)
        if combinator == "+":
            previous = el.previous()
            return previous is not None and self._full(previous, rule, k - 1)
        if combinator == "~":
            previous = el.previous()
            return previous is not None and self._any(previous, rule, k - 1, "~")
        return el.parent is not None and self._any(el.parent, rule, k - 1, " ")

    def _any(self, el: Element, rule: int, k: int, axis: str) -> bool:
        """Does ``el``, or an element before it on the axis (its ancestors, or
        its earlier siblings), match compound ``k`` with everything left of it?

        Answers are kept on each element, so every element is evaluated at
        most once per rule, position and axis, whatever the depth.
        """
        key = (rule * MAX_COMPOUNDS + k) * 2 + (axis == "~")
        chain: list[Element] = []
        node: Element | None = el
        known = False
        while node is not None:
            self.budget.spend()
            cached = node.memo.get(key)
            if cached is not None:
                known = cached
                break
            chain.append(node)
            node = node.parent if axis == " " else node.previous()
        for item in reversed(chain):
            known = known or self._full(item, rule, k)
            item.memo[key] = known
        return known


def cascade(
    matched: list[Rule],
    inline: Declarations,
    variables: dict[str, str],
    budget: Budget | None = None,
) -> tuple[dict[str, str], dict[str, str], set[str]]:
    """The winning value of each property, the custom properties in effect,
    and the properties whose value came from a variable. Pages switch themes
    by redefining variables, often in stylesheets Kestral cannot see.

    Rules apply by (``!important``, specificity, source order); an inline
    style beats any rule unless the rule is ``!important`` and the inline
    declaration is not. ``var()`` is resolved against the custom properties
    the element inherits and sets.
    """
    best: dict[str, tuple[tuple[int, int, int, Specificity, int], str]] = {}
    for rule in matched:
        if budget is not None:
            budget.spend(len(rule.declarations))
        for prop, (value, important) in rule.declarations.items():
            # Unlayered rules beat layered ones; for !important, the reverse.
            layer = int(rule.layered) if important else int(not rule.layered)
            rank = (int(important), 0, layer, rule.selector.specificity, rule.order)
            if prop not in best or rank > best[prop][0]:
                best[prop] = (rank, value)
    for prop, (value, important) in inline.items():
        rank = (int(important), 1, 0, (0, 0, 0), 0)
        if prop not in best or rank > best[prop][0]:
            best[prop] = (rank, value)
    custom = {p: v for p, (_, v) in best.items() if p.startswith("--")}
    if custom:
        if budget is not None:
            budget.spend(len(variables) + len(custom))
        variables = {**variables, **custom}
        if len(variables) > MAX_CUSTOM_PROPERTIES:
            raise TooComplex
    values: dict[str, str] = {}
    guessed: set[str] = set()
    for prop, (_, value) in best.items():
        if prop.startswith("--"):
            continue
        if "var(" in value:
            value, _ = resolve(value, variables)
            guessed.add(prop)
        values[prop] = value
    return values, variables, guessed
