const express = require("express");
const controllers = require("../../controllers/auth");
const router = express.Router();
const upload = require("../../middlewares/upload");
const auth = require("../../middlewares/authMiddleware");
router.post("/register", controllers.register);

router.post("/login", controllers.login);

router.post("/logout", auth, controllers.logout);

router.get("/current", auth, controllers.current);
router.patch(
  "/avatars",
  auth,
  upload.single("avatar"),
  controllers.uploadAvatar
);

router.get("/verify/:token", controllers.verifyEmail);
router.post("/verify", controllers.verifyAgainEmail);
module.exports = router;
