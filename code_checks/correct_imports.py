# type: ignore
import re

from pylint.checkers import BaseChecker


class RestrictImportChecker(BaseChecker):
    __implements__ = (BaseChecker,)

    name = "restrict-import-checker"
    msgs = {
        "W7001": (
            "Direct import from '%s' module is forbidden. Use module-level import instead.",
            "forbidden-import",
            "Used when a forbidden direct import is detected.",
        ),
    }

    # Specify the module paths to restrict (e.g., "rozert_pay.payment.models")
    restricted_module_patterns = [
        re.compile(r"rozert_pay.*?\.models\.?.*"),
    ]

    def visit_importfrom(self, node):
        # Triggered on `from ... import ...` statements
        module_name = node.modname
        for pattern in self.restricted_module_patterns:
            if pattern.match(module_name):
                self.add_message("forbidden-import", node=node, args=(module_name,))
                break


def register(linter):  # type: ignore  # pragma: no cover
    linter.register_checker(RestrictImportChecker(linter))
