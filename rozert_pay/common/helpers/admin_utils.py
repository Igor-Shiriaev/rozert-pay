from typing import TypedDict

from django.utils.functional import Promise
from django.utils.html import format_html, format_html_join
from django.utils.safestring import SafeString


class LinkItem(TypedDict):
    name: str | Promise
    link: str


def make_links(data: list[LinkItem]) -> SafeString:
    if len(data) == 1:
        item = data[0]
        return format_html('<a href="{}">{}</a>', item["link"], item["name"])

    list_items = format_html_join(
        "",
        '<li><a href="{}" style="white-space: nowrap">{}</a></li>',
        ((item["link"], item["name"]) for item in data),
    )
    return format_html("<ul>{}</ul>", list_items)
