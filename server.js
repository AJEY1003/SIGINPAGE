
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const cors = require('cors');

const app = express();
app.use(cors());
app.use(express.json());
mongoose.connect('mongodb://localhost:27017/userInfo')
  .then(() => console.log('Connected to MongoDB'))
  .catch(err => console.error('Error connecting to MongoDB:', err));

const userSchema = new mongoose.Schema({
  name: { type: String, required: true },
  password: { type: String, required: true },
  email: { type: String, required: true }
}, { collection: 'userdb' });

const User = mongoose.model('User', userSchema);

app.post('/register', async (req, res) => {
  try {
    const { name, password, confirmPassword, email } = req.body;

    if (!name || !password || !confirmPassword || !email) {
      return res.status(400).send({ error: 'All fields are required' });
    }

    if (password !== confirmPassword) {
      return res.status(400).send({ error: 'Passwords do not match' });
    }

    const emailRegex = /\S+@\S+\.\S+/;
    if (!emailRegex.test(email)) {
      return res.status(400).send({ error: 'Invalid email format' });
    }

    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).send({ error: 'User already exists' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const user = new User({ name, password: hashedPassword, email });
    await user.save();

    res.status(201).send({ success: true, message: 'User registered successfully!' });
  } catch (error) {
    console.error(error);
    res.status(500).send({ error: 'Error registering user.' });
  }
});


app.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    
    if (!email || !password) {
      return res.status(400).send({ error: 'Email and password are required' });
    }

    
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(400).send({ error: 'User does not exist' });
    }

    
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).send({ error: 'Invalid password' });
    }

    
    res.status(200).send({ success: true, message: 'Login successful!' });
  } catch (error) {
    console.error(error);
    res.status(500).send({ error: 'Error logging in user.' });
  }
});


app.get('/admin', async (req, res) => {
  try {
    // Fetch all user details
    const users = await User.find({}, { password: 0 }); // Exclude password for security
    res.status(200).send({ success: true, users });
  } catch (error) {
    console.error(error);
    res.status(500).send({ error: 'Error fetching user details.' });
  }
});

const PORT = 5000;
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});

