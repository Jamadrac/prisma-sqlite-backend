const express = require("express");
const { PrismaClient } = require("@prisma/client");

const router = express.Router();
const prisma = new PrismaClient();

// Create a new article
router.post("/", async (req, res) => {
  try {
    const { title, content, category } = req.body;
    const article = await prisma.article.create({
      data: { title, content, category },
    });
    res.status(201).json(article);
  } catch (error) {
    res.status(500).json({ error: "Failed to create article" });
  }
});

// Get all articles
router.get("/", async (req, res) => {
  try {
    const articles = await prisma.article.findMany();
    res.json(articles);
  } catch (error) {
    res.status(500).json({ error: "Failed to fetch articles" });
  }
});

// Get an article by ID
router.get("/:id", async (req, res) => {
  try {
    const { id } = req.params;
    const article = await prisma.article.findUnique({
      where: { id: parseInt(id) },
    });
    if (!article) {
      return res.status(404).json({ error: "Article not found" });
    }
    res.json(article);
  } catch (error) {
    res.status(500).json({ error: "Failed to fetch article" });
  }
});

// Get articles by category
router.get("/category/:category", async (req, res) => {
  try {
    const { category } = req.params;
    const articles = await prisma.article.findMany({ where: { category } });
    res.json(articles);
  } catch (error) {
    res.status(500).json({ error: "Failed to fetch articles" });
  }
});

// Delete an article by ID
router.delete("/:id", async (req, res) => {
  try {
    const { id } = req.params;
    await prisma.article.delete({ where: { id: parseInt(id) } });
    res.json({ message: "Article deleted successfully" });
  } catch (error) {
    res.status(500).json({ error: "Failed to delete article" });
  }
});

module.exports = router;