"""Decide which application a website name belongs to.

Example: "r3---sn-abc.googlevideo.com"  ->  no match
         "www.youtube.com"              ->  "YouTube"
"""

# (app name, keywords found anywhere in the name, exact domains)
# The list is checked top to bottom and the first match wins.
APP_RULES = [
    ("Google",     ["google", "gstatic", "googleapis", "ggpht", "gvt1"], []),
    ("YouTube",    ["youtube", "ytimg", "yt3.ggpht"],                    ["youtu.be"]),
    ("Facebook",   ["facebook", "fbcdn", "fbsbx"],                       ["fb.com", "meta.com"]),
    ("Instagram",  ["instagram", "cdninstagram"],                        []),
    ("WhatsApp",   ["whatsapp"],                                         ["wa.me"]),
    ("Twitter/X",  ["twitter", "twimg"],                                 ["x.com", "t.co"]),
    ("Netflix",    ["netflix", "nflxvideo", "nflximg"],                  []),
    ("Amazon",     ["amazon", "amazonaws", "cloudfront", "aws"],         []),
    ("Microsoft",  ["microsoft", "office", "azure", "outlook", "bing"],  ["msn.com", "live.com"]),
    ("Apple",      ["apple", "icloud", "mzstatic", "itunes"],            []),
    ("Telegram",   ["telegram"],                                         ["t.me"]),
    ("TikTok",     ["tiktok", "tiktokcdn", "bytedance"],                 ["musical.ly"]),
    ("Spotify",    ["spotify"],                                          ["scdn.co"]),
    ("Zoom",       ["zoom"],                                             []),
    ("Discord",    ["discord", "discordapp"],                            []),
    ("GitHub",     ["github", "githubusercontent"],                      []),
    ("Cloudflare", ["cloudflare", "cf-"],                                []),
]

# All names we can report, used to check --block-app spelling.
KNOWN_APPS = [name for name, _, _ in APP_RULES] + ["HTTP", "HTTPS", "DNS", "Unknown"]


def identify_app(host):
    """Return the app name for a website name like "www.youtube.com"."""
    host = host.lower()

    for app, keywords, domains in APP_RULES:
        if any(word in host for word in keywords):
            return app
        # "x.com" must match "x.com" or "www.x.com", but not "netflix.com"
        if any(host == d or host.endswith("." + d) for d in domains):
            return app

    return "HTTPS"   # we saw a name, but don't know the app
