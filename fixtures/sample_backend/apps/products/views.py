"""Safe search view with whitelist mitigation."""

from apps.products.models import Product


ALLOWED_FIELDS = ["name", "status", "category"]


class SafeSearchView:
    def get(self, request):
        # Whitelist keys before unpacking into ORM filter
        filters = {
            k: v for k, v in request.GET.items() if k in ALLOWED_FIELDS
        }
        return Product.objects.filter(**filters)
