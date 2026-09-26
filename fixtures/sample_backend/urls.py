"""URL routes for the sample backend."""

from django.urls import path

from apps.search.views import SearchAPIView
from apps.auth.views import RefreshTokenView
from apps.products.views import SafeSearchView


urlpatterns = [
    path("api/search", SearchAPIView.as_view(), name="search"),
    path("api/auth/refresh", RefreshTokenView.as_view(), name="refresh"),
    path("api/products/safe-search", SafeSearchView.as_view(), name="safe-search"),
]
