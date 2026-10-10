import { useState } from 'react';
import {
  ActivityIndicator, Image, KeyboardAvoidingView, Platform, Pressable,
  SafeAreaView, ScrollView, StyleSheet, Text, TextInput, View,
} from 'react-native';
import { StatusBar } from 'expo-status-bar';
import * as ImagePicker from 'expo-image-picker';

const API_URL = (process.env.EXPO_PUBLIC_API_URL || 'https://your-project.vercel.app').replace(/\/$/, '');

const RISK = {
  CRITICAL: { color: '#B91C1C', bg: '#FEE2E2', label: 'Critical risk' },
  HIGH:     { color: '#C2410C', bg: '#FFEDD5', label: 'High risk' },
  MEDIUM:   { color: '#A16207', bg: '#FEF9C3', label: 'Medium risk' },
  LOW:      { color: '#15803D', bg: '#DCFCE7', label: 'Low risk' },
};

const MODES = [
  { key: 'sms', label: 'Text' },
  { key: 'email', label: 'Email' },
  { key: 'screenshot', label: 'Screenshot' },
];

async function postJson(path, body) {
  const res = await fetch(`${API_URL}${path}`, body instanceof FormData
    ? { method: 'POST', body }
    : { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.error || `Request failed (${res.status})`);
  return data;
}

export default function App() {
  const [mode, setMode] = useState('sms');
  const [sender, setSender] = useState('');
  const [subject, setSubject] = useState('');
  const [message, setMessage] = useState('');
  const [preview, setPreview] = useState(null);
  const [busy, setBusy] = useState(null);
  const [error, setError] = useState('');
  const [result, setResult] = useState(null);

  async function pickScreenshot() {
    setError('');
    const picked = await ImagePicker.launchImageLibraryAsync({ mediaTypes: ['images'], quality: 0.8 });
    if (picked.canceled) return;
    const asset = picked.assets[0];
    setPreview(asset.uri);
    setBusy('Reading screenshot…');
    try {
      const form = new FormData();
      form.append('image', {
        uri: asset.uri,
        name: asset.fileName || 'screenshot.jpg',
        type: asset.mimeType || 'image/jpeg',
      });
      const data = await postJson('/api/extract', form);
      setMessage(data.text || '');
      setSender(data.sender || '');
      setSubject(data.subject || '');
      setMode(data.mode === 'email' ? 'email' : 'sms');
    } catch (e) {
      setError(e.message);
    } finally {
      setBusy(null);
    }
  }

  async function scan() {
    if (!message.trim() && !sender.trim()) {
      setError('Paste a message or enter a sender first.');
      return;
    }
    setError('');
    setResult(null);
    setBusy('Checking for scams…');
    try {
      setResult(await postJson('/api/scan', { sender, subject, message, mode, userId: 'public' }));
    } catch (e) {
      setError(e.message);
    } finally {
      setBusy(null);
    }
  }

  function reset() {
    setSender(''); setSubject(''); setMessage(''); setPreview(null); setResult(null); setError('');
  }

  const risk = result && (RISK[result.risk_level] || RISK.LOW);

  return (
    <SafeAreaView style={s.safe}>
      <StatusBar style="dark" />
      <KeyboardAvoidingView style={{ flex: 1 }} behavior={Platform.OS === 'ios' ? 'padding' : undefined}>
        <ScrollView contentContainerStyle={s.page} keyboardShouldPersistTaps="handled">
          <Text style={s.brand}>PhishGuard</Text>
          <Text style={s.tagline}>Check a text, email or screenshot before you click.</Text>

          <View style={s.tabs}>
            {MODES.map(m => (
              <Pressable key={m.key} onPress={() => setMode(m.key)}
                style={[s.tab, mode === m.key && s.tabActive]}>
                <Text style={[s.tabText, mode === m.key && s.tabTextActive]}>{m.label}</Text>
              </Pressable>
            ))}
          </View>

          <View style={s.card}>
            {mode === 'screenshot' ? (
              <Pressable style={s.upload} onPress={pickScreenshot} disabled={!!busy}>
                {preview
                  ? <Image source={{ uri: preview }} style={s.preview} resizeMode="contain" />
                  : <Text style={s.uploadText}>Tap to choose a screenshot</Text>}
              </Pressable>
            ) : (
              <>
                <Text style={s.label}>{mode === 'email' ? 'From (email address)' : 'From (phone number)'}</Text>
                <TextInput style={s.input} value={sender} onChangeText={setSender}
                  placeholder={mode === 'email' ? 'support@paypa1.com' : '+1 555 123 4567'}
                  autoCapitalize="none" maxLength={256} />
                {mode === 'email' && (
                  <>
                    <Text style={s.label}>Subject</Text>
                    <TextInput style={s.input} value={subject} onChangeText={setSubject} maxLength={300} />
                  </>
                )}
                <Text style={s.label}>Message</Text>
                <TextInput style={[s.input, s.body]} value={message} onChangeText={setMessage}
                  placeholder="Paste the message here" multiline textAlignVertical="top" maxLength={10000} />
              </>
            )}

            <Pressable style={[s.button, busy && s.buttonDisabled]} onPress={scan} disabled={!!busy}>
              {busy
                ? <View style={s.row}><ActivityIndicator color="#fff" /><Text style={s.buttonText}>  {busy}</Text></View>
                : <Text style={s.buttonText}>Check message</Text>}
            </Pressable>
            {!!error && <Text style={s.error}>{error}</Text>}
          </View>

          {result && (
            <View style={[s.card, { borderColor: risk.color, borderWidth: 2 }]}>
              <View style={[s.badge, { backgroundColor: risk.bg }]}>
                <Text style={[s.badgeText, { color: risk.color }]}>
                  {result.is_scam ? 'Likely scam' : 'Looks safe'} · {risk.label} · {result.score}/100
                </Text>
              </View>
              {!!result.scam_type && <Text style={s.scamType}>{result.scam_type}</Text>}
              {!!result.reasoning && <Text style={s.text}>{result.reasoning}</Text>}

              {result.red_flags?.length > 0 && (
                <>
                  <Text style={s.section}>Warning signs</Text>
                  {result.red_flags.map((f, i) => <Text key={i} style={s.bullet}>• {f}</Text>)}
                </>
              )}
              {result.recommended_actions?.length > 0 && (
                <>
                  <Text style={s.section}>What to do</Text>
                  {result.recommended_actions.map((a, i) => <Text key={i} style={s.bullet}>• {a}</Text>)}
                </>
              )}

              <Pressable style={s.secondary} onPress={reset}>
                <Text style={s.secondaryText}>Check another message</Text>
              </Pressable>
            </View>
          )}
        </ScrollView>
      </KeyboardAvoidingView>
    </SafeAreaView>
  );
}

const s = StyleSheet.create({
  safe: { flex: 1, backgroundColor: '#F0F4F8' },
  page: { padding: 16, paddingTop: Platform.OS === 'android' ? 40 : 16, gap: 14 },
  brand: { fontSize: 28, fontWeight: '800', color: '#1E3A8A' },
  tagline: { fontSize: 15, color: '#475569', marginTop: -8 },
  tabs: { flexDirection: 'row', backgroundColor: '#E2E8F0', borderRadius: 12, padding: 4 },
  tab: { flex: 1, paddingVertical: 10, borderRadius: 9, alignItems: 'center' },
  tabActive: { backgroundColor: '#fff' },
  tabText: { fontSize: 15, color: '#475569', fontWeight: '600' },
  tabTextActive: { color: '#2563EB' },
  card: { backgroundColor: '#fff', borderRadius: 16, padding: 16, gap: 8, borderWidth: 1, borderColor: '#E2E8F0' },
  label: { fontSize: 13, fontWeight: '600', color: '#334155', marginTop: 4 },
  input: { borderWidth: 1, borderColor: '#CBD5E1', borderRadius: 10, padding: 12, fontSize: 16, color: '#0F172A' },
  body: { minHeight: 140 },
  upload: { borderWidth: 2, borderStyle: 'dashed', borderColor: '#93C5FD', borderRadius: 12,
            minHeight: 180, alignItems: 'center', justifyContent: 'center', backgroundColor: '#EFF6FF' },
  uploadText: { color: '#2563EB', fontSize: 16, fontWeight: '600' },
  preview: { width: '100%', height: 260 },
  button: { backgroundColor: '#2563EB', borderRadius: 12, paddingVertical: 14, alignItems: 'center', marginTop: 8 },
  buttonDisabled: { opacity: 0.7 },
  buttonText: { color: '#fff', fontSize: 16, fontWeight: '700' },
  row: { flexDirection: 'row', alignItems: 'center' },
  error: { color: '#B91C1C', fontSize: 14 },
  badge: { alignSelf: 'flex-start', borderRadius: 999, paddingHorizontal: 12, paddingVertical: 6 },
  badgeText: { fontWeight: '700', fontSize: 14 },
  scamType: { fontSize: 18, fontWeight: '700', color: '#0F172A' },
  text: { fontSize: 15, color: '#334155', lineHeight: 22 },
  section: { fontSize: 15, fontWeight: '700', color: '#0F172A', marginTop: 8 },
  bullet: { fontSize: 15, color: '#334155', lineHeight: 22 },
  secondary: { borderWidth: 1, borderColor: '#2563EB', borderRadius: 12, paddingVertical: 12, alignItems: 'center', marginTop: 8 },
  secondaryText: { color: '#2563EB', fontSize: 15, fontWeight: '600' },
});
