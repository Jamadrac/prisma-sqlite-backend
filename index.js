// In server.js or app.js
const express = require("express");
const bodyParser = require("body-parser");
const cors = require("cors");
const morgan = require("morgan");
const articleRoutes = require("./routes/articleRoutes");

const app = express();
const PORT = 3000;

// Enable CORS
app.use(cors());

// Configure Morgan middleware for logging
// This will log: method url status response-time ms - response-body-size
app.use(
  morgan(":method :url :status :response-time ms - :res[content-length]")
);

// Create a custom Morgan token for request body
morgan.token("body", (req) => JSON.stringify(req.body));

// Add another Morgan middleware with custom format to log request body
app.use(morgan(":method :url :status :body"));

// Parse JSON and URL-encoded requests
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// Mount the article routes with '/articles' path
app.use("/articles", articleRoutes);

app.listen(PORT, () => {
  console.log(`Server is running on http://localhost:${PORT}`);
});
