 

const express = require('express');
const mongoose = require('mongoose');
const multer = require('multer');
const cors = require('cors');
const tesseract = require('tesseract.js');
const path = require('path');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
const PORT = process.env.PORT || 5000;

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));


// MongoDB Connection
mongoose.connect('mongodb://localhost:27017/imageUploadDB', { useNewUrlParser: true, useUnifiedTopology: true })
    .then(() => console.log('MongoDB connected'))
    .catch(err => console.log(err));

// Multer configuration
const storage = multer.memoryStorage();
const upload = multer({ storage: storage });

// Image Schema
const ImageSchema = new mongoose.Schema({
    filename: String,
    contentType: String,
    imageBase64: String,
    extractedText: String,
    boldWords: [String],
    uploadedAt: { type: Date, default: Date.now }
});

const Image = mongoose.model('Image', ImageSchema);

const userSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    password: { type: String, required: true }
  });
  
  const User = mongoose.model('User', userSchema);

// Function to identify bold words (dummy function, replace with actual implementation)
function identifyBoldWords(text) {
    // Placeholder logic: Identify words surrounded by '**'
    const boldWords = [];
    const regex = /\*\*(.*?)\*\*/g;
    let match;
    while ((match = regex.exec(text)) !== null) {
        boldWords.push(match[1]);
    }
    return boldWords;
}





const auth = (req, res, next) => {
    const token = req.header('x-auth-token');
    if (!token) return res.status(401).send('Access denied. No token provided.');
  
    try {
      const decoded = jwt.verify(token, 'jwtPrivateKey');
      req.user = decoded;
      next();
    } catch (ex) {
      res.status(400).send('Invalid token.');
    }
  };
  
  // Register route
  app.post('/register', async (req, res) => {
    try {
      const { username, password } = req.body;
      console.log('Received registration request:', username);
  
      let user = await User.findOne({ username });
      if (user) {
        console.log('User already registered:', username);
        return res.status(400).send('User already registered.');
      }
  
      user = new User({ username, password });
      const salt = await bcrypt.genSalt(10);
      user.password = await bcrypt.hash(user.password, salt);
  
      await user.save();
  
      const token = jwt.sign({ _id: user._id }, 'jwtPrivateKey');
      console.log('Generated token:', token);
      res.json({token});
    } catch (error) {
      console.error('Registration error:', error);
      res.status(500).send('Internal Server Error');
    }
  });
  
  
  // Login route
  app.post('/login', async (req, res) => {
    const { username, password } = req.body;
  
    const user = await User.findOne({ username });
    if (!user) return res.status(400).send('Invalid username or password.');
  
    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) return res.status(400).send('Invalid username or password.');
  
    const token = jwt.sign({ _id: user._id }, 'jwtPrivateKey');
    console.log(token)
    res.json({token});
  });
  


// Routes
app.post('/upload', upload.single('image'), async (req, res) => {
    try {
        const imageBase64 = req.file.buffer.toString('base64');
        const imageBuffer = req.file.buffer;

        // Use Tesseract.js to extract text from image
        const result = await tesseract.recognize(imageBuffer, 'eng');
        console.log(result);

        const { data: { text } } = result;

        // Identify bold words in the extracted text (this needs a real implementation)
        const boldWords = identifyBoldWords(text);

        const newImage = new Image({
            filename: req.file.originalname,
            contentType: req.file.mimetype,
            imageBase64: imageBase64,
            extractedText: text,
            boldWords: boldWords
        });

        await newImage.save();
        res.status(201).json(newImage);
    } catch (error) {
        res.status(500).json({ message: 'Server Error', error });
    }
});

app.get('/images', async (req, res) => {
    try {
        const images = await Image.find();
        res.status(200).json(images);
    } catch (error) {
        res.status(500).json({ message: 'Server Error', error });
    }
});

app.listen(PORT, () => console.log(`Server running on port ${PORT}`));


