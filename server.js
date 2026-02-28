const express = require('express');
const cors = require('cors');
const { createClient } = require('@supabase/supabase-js');
const bcrypt = require('bcryptjs');
require('dotenv').config();

const app = express();
app.use(cors());
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ limit: '10mb', extended: true }));

const supabaseUrl = process.env.SUPABASE_URL;
const supabaseKey = process.env.SUPABASE_ANON_KEY;
const supabase = createClient(supabaseUrl, supabaseKey);

// --- Profiles ---

// Create new profile
app.post('/api/profiles', async (req, res) => {
  const { name, password, avatar_url } = req.body;
  if (!name || !password) return res.status(400).json({ error: 'Name and password required' });

  try {
    const salt = await bcrypt.genSalt(10);
    const password_hash = await bcrypt.hash(password, salt);

    const { data, error } = await supabase
      .from('profiles')
      .insert([{ name, password_hash, avatar_url }])
      .select('id, name, avatar_url, created_at')
      .single();

    if (error) throw error;
    res.status(201).json(data);
  } catch (err) {
    if (err.code === '23505') return res.status(409).json({ error: 'Profile name already exists' });
    res.status(500).json({ error: err.message });
  }
});

// List all profiles (for the selection screen)
app.get('/api/profiles', async (req, res) => {
  const { data, error } = await supabase
    .from('profiles')
    .select('id, name, avatar_url, created_at')
    .order('created_at', { ascending: false });

  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

// Login
app.post('/api/profiles/login', async (req, res) => {
  const { profile_id, password } = req.body;
  if (!profile_id || !password) return res.status(400).json({ error: 'Profile ID and password required' });

  const { data: profile, error } = await supabase
    .from('profiles')
    .select('*')
    .eq('id', profile_id)
    .single();

  if (error || !profile) return res.status(404).json({ error: 'Profile not found' });

  const isMatch = await bcrypt.compare(password, profile.password_hash);
  if (!isMatch) return res.status(401).json({ error: 'Invalid password' });

  const { password_hash, ...safeProfile } = profile;
  res.json(safeProfile);
});

// Update profile
app.put('/api/profiles/:id', async (req, res) => {
  const { name, password, avatar_url } = req.body;
  const updates = {};

  if (name) updates.name = name;
  if (avatar_url !== undefined) updates.avatar_url = avatar_url;

  if (password) {
    const salt = await bcrypt.genSalt(10);
    updates.password_hash = await bcrypt.hash(password, salt);
  }

  const { data, error } = await supabase
    .from('profiles')
    .update(updates)
    .eq('id', req.params.id)
    .select('id, name, avatar_url, created_at')
    .single();

  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

// Delete profile
app.delete('/api/profiles/:id', async (req, res) => {
  const { error } = await supabase
    .from('profiles')
    .delete()
    .eq('id', req.params.id);

  if (error) return res.status(500).json({ error: error.message });
  res.status(204).send();
});

// --- Checklists ---

// Create checklist
app.post('/api/checklists', async (req, res) => {
  const { profile_id, title } = req.body;
  if (!profile_id || !title) return res.status(400).json({ error: 'Profile ID and title required' });

  const { data, error } = await supabase
    .from('checklists')
    .insert([{ profile_id, title }])
    .select()
    .single();

  if (error) return res.status(500).json({ error: error.message });
  res.status(201).json(data);
});

// List checklists for a profile
app.get('/api/checklists', async (req, res) => {
  const { profile_id } = req.query;
  if (!profile_id) return res.status(400).json({ error: 'Profile ID required' });

  const { data, error } = await supabase
    .from('checklists')
    .select('*')
    .eq('profile_id', profile_id)
    .order('created_at', { ascending: false });

  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

// Get a specific checklist
app.get('/api/checklists/:id', async (req, res) => {
  const { data, error } = await supabase
    .from('checklists')
    .select('*')
    .eq('id', req.params.id)
    .single();

  if (error) return res.status(404).json({ error: 'Checklist not found' });
  res.json(data);
});

// Update checklist
app.put('/api/checklists/:id', async (req, res) => {
  const { title } = req.body;
  const { data, error } = await supabase
    .from('checklists')
    .update({ title })
    .eq('id', req.params.id)
    .select()
    .single();

  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

// Delete checklist
app.delete('/api/checklists/:id', async (req, res) => {
  const { error } = await supabase
    .from('checklists')
    .delete()
    .eq('id', req.params.id);

  if (error) return res.status(500).json({ error: error.message });
  res.status(204).send();
});

// --- Tasks ---

// Create a task (main task or sub-task)
app.post('/api/tasks', async (req, res) => {
  const { checklist_id, parent_id, title, order_num, start_time, end_time } = req.body;

  const { data, error } = await supabase
    .from('tasks')
    .insert([{ checklist_id, parent_id: parent_id || null, title, order_num, start_time, end_time }])
    .select()
    .single();

  if (error) return res.status(500).json({ error: error.message });
  res.status(201).json(data);
});

// Get all tasks for a checklist
app.get('/api/checklists/:id/tasks', async (req, res) => {
  const { data, error } = await supabase
    .from('tasks')
    .select('*')
    .eq('checklist_id', req.params.id)
    .order('order_num', { ascending: true }); // Sub-tasks will also be ordered by their own order_num

  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

// Update a task
app.put('/api/tasks/:id', async (req, res) => {
  const { title, is_completed, order_num, start_time, end_time } = req.body;

  const updates = {};
  if (title !== undefined) updates.title = title;
  if (is_completed !== undefined) updates.is_completed = is_completed;
  if (order_num !== undefined) updates.order_num = order_num;
  if (start_time !== undefined) updates.start_time = start_time;
  if (end_time !== undefined) updates.end_time = end_time;

  const { data, error } = await supabase
    .from('tasks')
    .update(updates)
    .eq('id', req.params.id)
    .select()
    .single();

  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

// Delete a task
app.delete('/api/tasks/:id', async (req, res) => {
  const { error } = await supabase
    .from('tasks')
    .delete()
    .eq('id', req.params.id);

  if (error) return res.status(500).json({ error: error.message });
  res.status(204).send();
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});

module.exports = app;
