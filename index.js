const express = require("express");
const bodyParser = require("body-parser");
const articleRoutes = require("./routes/articleRoutes");

const app = express();
const PORT = 3000;

app.use(bodyParser.json());
app.use("/articles", articleRoutes);

app.listen(PORT, () => {
  console.log(`Server is running on http://localhost:${PORT}`);
});
