router.get("/orders", listOrders);
router.get("/orders/:id", requireUser, showOrder);
router.get("/health", showHealth);
