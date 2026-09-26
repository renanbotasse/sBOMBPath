"""Exploitable search views (intentional vulnerable fixture)."""

from apps.products.models import Product


class SearchAPIView:
    def post(self, request):
        term = request.GET["search"]
        results = self.filter_products(term)
        return results

    def filter_products(self, query):
        return Product.objects.filter(**{"search": query})


class SearchView:
    def get(self, request):
        search_query = request.GET["q"]
        return Product.objects.filter(**search_query)
