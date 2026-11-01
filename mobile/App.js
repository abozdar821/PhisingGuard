import { useCallback, useEffect, useRef, useState } from 'react';
import { ActivityIndicator, Alert, BackHandler, Linking, Platform, Pressable, StyleSheet, Text, View } from 'react-native';
import { SafeAreaView, SafeAreaProvider } from 'react-native-safe-area-context';
import { StatusBar } from 'expo-status-bar';
import { WebView } from 'react-native-webview';

const APP_URL = (process.env.EXPO_PUBLIC_APP_URL || '').trim().replace(/\/$/, '');
const APP_ORIGIN = /^https:\/\/[^/]+/i.test(APP_URL) && !APP_URL.includes('your-project') ? new URL(APP_URL).origin : null;

function hostOf(url) {
  try { return new URL(url).host; } catch { return url; }
}

// Messages being checked are often scams, so nothing outside PhishGuard opens inside the app.
function confirmExternal(url) {
  if (/^(tel|sms|mailto):/i.test(url)) {
    Linking.openURL(url).catch(() => {});
    return;
  }
  if (!/^https?:/i.test(url)) return;
  Alert.alert(
    'Leave PhishGuard?',
    `This opens ${hostOf(url)} in your browser. Only continue if you trust this site.`,
    [{ text: 'Cancel', style: 'cancel' }, { text: 'Open', onPress: () => Linking.openURL(url).catch(() => {}) }],
  );
}

function Screen() {
  const web = useRef(null);
  const [canGoBack, setCanGoBack] = useState(false);
  const [failed, setFailed] = useState(false);

  useEffect(() => {
    if (Platform.OS !== 'android') return undefined;
    const sub = BackHandler.addEventListener('hardwareBackPress', () => {
      if (!canGoBack) return false;
      web.current?.goBack();
      return true;
    });
    return () => sub.remove();
  }, [canGoBack]);

  const allowLoad = useCallback(req => {
    const url = req.url;
    if (url === APP_ORIGIN || url.startsWith(APP_ORIGIN + '/') || /^(about|data|blob):/i.test(url)) return true;
    if (req.isTopFrame !== false) confirmExternal(url);
    return false;
  }, []);

  if (!APP_ORIGIN) {
    return (
      <View style={s.center}>
        <Text style={s.title}>PhishGuard isn't set up</Text>
        <Text style={s.body}>This build has no PhishGuard address. Set EXPO_PUBLIC_APP_URL to your https:// address and build again.</Text>
      </View>
    );
  }

  if (failed) {
    return (
      <View style={s.center}>
        <Text style={s.title}>Can't reach PhishGuard</Text>
        <Text style={s.body}>Check your internet connection and try again.</Text>
        <Pressable style={s.button} onPress={() => setFailed(false)}>
          <Text style={s.buttonText}>Try again</Text>
        </Pressable>
      </View>
    );
  }

  return (
    <WebView
      ref={web}
      source={{ uri: APP_URL }}
      originWhitelist={['http://*', 'https://*', 'about:*']}
      onShouldStartLoadWithRequest={allowLoad}
      onOpenWindow={e => confirmExternal(e.nativeEvent.targetUrl)}
      setSupportMultipleWindows={false}
      onNavigationStateChange={nav => setCanGoBack(nav.canGoBack)}
      onError={() => setFailed(true)}
      onContentProcessDidTerminate={() => web.current?.reload()}
      onRenderProcessGone={() => web.current?.reload()}
      startInLoadingState
      renderLoading={() => <ActivityIndicator style={StyleSheet.absoluteFill} size="large" color="#2563EB" />}
      domStorageEnabled
      allowsBackForwardNavigationGestures
      pullToRefreshEnabled
      allowFileAccess={false}
      style={s.web}
    />
  );
}

export default function App() {
  return (
    <SafeAreaProvider>
      <SafeAreaView style={s.safe} edges={['top', 'bottom']}>
        <StatusBar style="dark" />
        <Screen />
      </SafeAreaView>
    </SafeAreaProvider>
  );
}

const s = StyleSheet.create({
  safe: { flex: 1, backgroundColor: '#fff' },
  web: { flex: 1 },
  center: { flex: 1, alignItems: 'center', justifyContent: 'center', padding: 24, gap: 12 },
  title: { fontSize: 20, fontWeight: '700', color: '#0F172A' },
  body: { fontSize: 15, color: '#475569', textAlign: 'center' },
  button: { backgroundColor: '#2563EB', borderRadius: 12, paddingVertical: 12, paddingHorizontal: 24 },
  buttonText: { color: '#fff', fontSize: 16, fontWeight: '700' },
});
