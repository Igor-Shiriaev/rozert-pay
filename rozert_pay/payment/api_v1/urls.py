from django.urls import path
from rest_framework.routers import DefaultRouter
from rozert_pay.payment.api_v1 import views
from rozert_pay.payment.systems.d24_mercadopago.views import D24MercadoPagoViewSet

router = DefaultRouter()

router.register(r"wallet", views.WalletViewSet, basename="wallet")
router.register(r"transaction", views.TransactionViewSet, basename="transaction")

# Payment system specific views.
router.register("d24-mercadopago", D24MercadoPagoViewSet, basename="d24-mercadopago")

urlpatterns = router.urls + [
    path("callback/<str:system>/", views.CallbackView.as_view(), name="callback"),
    path("redirect/<str:system>/", views.RedirectView.as_view(), name="redirect"),
]
