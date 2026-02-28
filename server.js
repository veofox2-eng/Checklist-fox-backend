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
  const { profile_id, password } = req.body;

  if (!profile_id || !password) {
    return res.status(400).json({ error: 'Profile ID and password required for deletion' });
  }

  const { data: profile, error: profileError } = await supabase
    .from('profiles')
    .select('password_hash')
    .eq('id', profile_id)
    .single();

  if (profileError || !profile) return res.status(404).json({ error: 'Profile not found' });

  const isMatch = await bcrypt.compare(password, profile.password_hash);
  if (!isMatch) return res.status(401).json({ error: 'Invalid password' });

  const { error } = await supabase
    .from('checklists')
    .delete()
    .eq('id', req.params.id);

  if (error) return res.status(500).json({ error: error.message });
  res.status(204).send();
});

// --- Share Requests ---

// Send a share request
app.post('/api/checklists/:id/share', async (req, res) => {
  const { sender_id, receiver_name } = req.body;
  const checklist_id = req.params.id;

  if (!sender_id || !receiver_name) return res.status(400).json({ error: 'Sender ID and receiver name required' });

  const { data: receiver, error: receiverError } = await supabase
    .from('profiles')
    .select('id')
    .eq('name', receiver_name)
    .single();

  if (receiverError || !receiver) return res.status(404).json({ error: 'Receiver profile not found' });

  const { data, error } = await supabase
    .from('share_requests')
    .insert([{ checklist_id, sender_id, receiver_id: receiver.id }])
    .select()
    .single();

  if (error) return res.status(500).json({ error: error.message });
  res.status(201).json(data);
});

// Get pending share requests for a profile
app.get('/api/profiles/:id/share-requests', async (req, res) => {
  const { data, error } = await supabase
    .from('share_requests')
    .select(`
      id, status, created_at, checklist_id,
      checklists ( title ),
      profiles!share_requests_sender_id_fkey ( name, avatar_url )
    `)
    .eq('receiver_id', req.params.id)
    .eq('status', 'pending')
    .order('created_at', { ascending: false });

  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

// Respond to a share request
app.post('/api/share-requests/:id/respond', async (req, res) => {
  const { action } = req.body; // 'accept' or 'reject'
  if (!['accept', 'reject'].includes(action)) return res.status(400).json({ error: 'Invalid action' });

  const { data: request, error: reqError } = await supabase
    .from('share_requests')
    .select('*')
    .eq('id', req.params.id)
    .single();

  if (reqError || !request) return res.status(404).json({ error: 'Request not found' });
  if (request.status !== 'pending') return res.status(400).json({ error: 'Request already processed' });

  const { error: updateError } = await supabase
    .from('share_requests')
    .update({ status: action === 'accept' ? 'accepted' : 'rejected' })
    .eq('id', req.params.id);

  if (updateError) return res.status(500).json({ error: updateError.message });

  if (action === 'accept') {
    const { data: originalChecklist, error: clError } = await supabase
      .from('checklists')
      .select('*')
      .eq('id', request.checklist_id)
      .single();

    if (clError) return res.status(500).json({ error: clError.message });

    const { data: newChecklist, error: newClError } = await supabase
      .from('checklists')
      .insert([{
        profile_id: request.receiver_id,
        title: originalChecklist.title,
        is_shared_copy: true
      }])
      .select()
      .single();

    if (newClError) return res.status(500).json({ error: newClError.message });

    const { data: tasks, error: tasksError } = await supabase
      .from('tasks')
      .select('*')
      .eq('checklist_id', request.checklist_id)
      .order('created_at', { ascending: true });

    if (tasksError) return res.status(500).json({ error: tasksError.message });

    const idMap = {};
    for (const task of tasks) {
      const newTaskData = {
        checklist_id: newChecklist.id,
        parent_id: task.parent_id ? idMap[task.parent_id] : null,
        title: task.title,
        description: task.description,
        order_num: task.order_num,
        start_time: task.start_time,
        end_time: task.end_time,
        allocated_time: task.allocated_time,
        is_completed: task.is_completed
      };

      const { data: newTask, error: nTError } = await supabase
        .from('tasks')
        .insert([newTaskData])
        .select()
        .single();

      if (!nTError && newTask) {
        idMap[task.id] = newTask.id;
      }
    }
    return res.json({ message: 'Accepted and cloned checklist' });
  }

  res.json({ message: 'Rejected share request' });
});

// --- Timer Logs ---

// Add a timer log
app.post('/api/checklists/:id/timer-logs', async (req, res) => {
  const { elapsed_seconds } = req.body;
  if (elapsed_seconds === undefined) return res.status(400).json({ error: 'Elapsed seconds required' });

  const { data, error } = await supabase
    .from('timer_logs')
    .insert([{ checklist_id: req.params.id, elapsed_seconds }])
    .select()
    .single();

  if (error) return res.status(500).json({ error: error.message });
  res.status(201).json(data);
});

// Get timer logs
app.get('/api/checklists/:id/timer-logs', async (req, res) => {
  const { data, error } = await supabase
    .from('timer_logs')
    .select('*')
    .eq('checklist_id', req.params.id)
    .order('created_at', { ascending: false });

  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

// --- Tasks ---

// Create a task (main task or sub-task)
app.post('/api/tasks', async (req, res) => {
  const { checklist_id, parent_id, title, description, order_num, start_time, end_time, allocated_time } = req.body;

  const { data, error } = await supabase
    .from('tasks')
    .insert([{ checklist_id, parent_id: parent_id || null, title, description, order_num, start_time, end_time, allocated_time }])
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
  const { title, description, is_completed, order_num, start_time, end_time, allocated_time } = req.body;

  const updates = {};
  if (title !== undefined) updates.title = title;
  if (description !== undefined) updates.description = description;
  if (is_completed !== undefined) updates.is_completed = is_completed;
  if (order_num !== undefined) updates.order_num = order_num;
  if (start_time !== undefined) updates.start_time = start_time;
  if (end_time !== undefined) updates.end_time = end_time;
  if (allocated_time !== undefined) updates.allocated_time = allocated_time;

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
