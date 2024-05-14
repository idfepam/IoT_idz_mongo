const express = require("express");
const mongoose = require("mongoose");
const bodyParser = require("body-parser");
const session = require("express-session");
const crypto = require("crypto");
const path = require("path");

const app = express();
const port = 3000;

// MongoDB connection
mongoose.connect("mongodb://localhost:27017/idz", {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});
const db = mongoose.connection;
db.on("error", console.error.bind(console, "connection error:"));
db.once("open", function () {
  console.log("Connected successfully to MongoDB");
});

// User and Contact Schemas
const Schema = mongoose.Schema;

const userSchema = new Schema({
  username: { type: String, unique: true, required: true },
  password: { type: String, required: true }
});

const contactSchema = new Schema({
  data: Schema.Types.Mixed,
  userId: { type: Schema.Types.ObjectId, ref: 'User' }
}, { strict: false });

const User = mongoose.model("User", userSchema);
const Contact = mongoose.model("Contact", contactSchema);

// Middleware
app.use(bodyParser.json());
app.use(session({
  secret: 'simple secret',
  resave: false,
  saveUninitialized: false,
}));

// Password hashing utility
function hashPassword(password) {
  return crypto.createHash('sha256').update(password).digest('hex');
}

// User registration
app.post("/api/register-user", async (req, res) => {
  try {
    const hashedPassword = hashPassword(req.body.password);
    const user = new User({ username: req.body.username, password: hashedPassword });
    await user.save();
    res.status(201).send({ message: "User registered successfully" });
  } catch (error) {
    res.status(400).send({ message: "Error registering user", error });
  }
});

// User login
app.post("/api/login", async (req, res) => {
  const user = await User.findOne({ username: req.body.username });
  if (!user || user.password !== hashPassword(req.body.password)) {
    return res.status(401).send({ message: "Invalid credentials" });
  }
  req.session.user = user;
  res.redirect("/");
});

// User logout
app.get("/logout", (req, res) => {
  req.session.destroy(err => {
    if (err) {
      return res.status(500).send({ message: "Could not log out, please try again." });
    }
    res.redirect("/login.html");
  });
});

// Middleware to check if user is logged in
function checkLogin(req, res, next) {
  if (req.session.user) {
    next();
  } else {
    res.redirect("/login.html");
  }
}

// Adjust existing endpoints to incorporate user context
app.post("/register", checkLogin, async (req, res) => {
  const newContact = new Contact({ data: req.body, userId: req.session.user._id });
  try {
    await newContact.save();
    res.status(201).send(newContact);
  } catch (error) {
    res.status(400).send(error);
  }
});

// Retrieve all contacts for the logged-in user
app.get("/contacts", checkLogin, async (req, res) => {
  try {
    const contacts = await Contact.find({ userId: req.session.user._id });
    res.send(contacts);
  } catch (error) {
    res.status(500).send(error);
  }
});

// Get a specific contact
app.get("/contacts/:id", checkLogin, async (req, res) => {
  try {
      const contact = await Contact.findOne({
          _id: req.params.id,
          userId: req.session.user._id  
      });
      if (!contact) {
          return res.status(404).send({ message: "Contact not found" });
      }
      res.json(contact);
  } catch (error) {
      console.error("Error fetching contact:", error);
      res.status(500).send({ message: "Error retrieving contact", error: error.message });
  }
});


app.put("/contacts/:id", checkLogin, async (req, res) => {
  try {
    const updateData = req.body;  
    const updatedContact = await Contact.findOneAndUpdate(
      { _id: req.params.id, userId: req.session.user._id },
      { $set: updateData },  
      { new: true }
    );
    if (updatedContact) {
      res.json(updatedContact);
    } else {
      res.status(404).send({ message: "Contact not found or not yours to update" });
    }
  } catch (error) {
    console.error("Error updating contact:", error);
    res.status(500).send({ message: "Error updating contact", error: error.message });
  }
});


// Delete a contact
app.delete("/contacts/:id", checkLogin, async (req, res) => {
  try {
    const result = await Contact.findOneAndDelete({ _id: req.params.id, userId: req.session.user._id });
    if (result) {
      res.status(204).send();
    } else {
      res.status(404).send({ message: "Contact not found or not yours to delete" });
    }
  } catch (error) {
    res.status(500).send(error);
  }
});

// Search contacts for the logged-in user
app.get("/search", checkLogin, async (req, res) => {
  try {
    const searchQuery = { userId: req.session.user._id };
    for (let key in req.query) {
      searchQuery[`data.${key}`] = { $regex: new RegExp(req.query[key], "i") };
    }
    const contacts = await Contact.find(searchQuery);
    res.send(contacts);
  } catch (error) {
    res.status(500).send(error);
  }
});

// Route to serve HTML file
app.get("/", checkLogin, (req, res) => {
  res.sendFile(path.join(__dirname, "index.html"));
});

// Serve login and register HTML
app.get("/login.html", (req, res) => {
  if (req.session.user) {
    res.redirect("/");
  } else {
    res.sendFile(path.join(__dirname, "login.html"));
  }
});

// Start server
app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
