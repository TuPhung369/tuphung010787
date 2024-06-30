import express from "express";
const router = express.Router();

router.get("/", (req, res) => {
  res.json("Using router1 GET method!");
});
router.post("/", (req, res) => {
  console.log(req.body);
  res.json(
    "Using router1 POST method!" +
      req.body.username +
      "_" +
      req.body.password +
      "_" +
      req.headers.location
  );
});
router.get("/product/", (req, res) => {
  res.json("Product from router1!");
});
router.get("/cart", (req, res) => {
  res.json("Cart from router1!");
});
router.get("/:id", (req, res) => {
  res.json("Hello from router1!" + req.params.id);
});
export default router;
