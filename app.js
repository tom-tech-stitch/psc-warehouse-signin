// PSC Warehouse sign-in and approval page for the Supabase Auth OAuth server.
// Supabase sends people here with ?authorization_id=... when they connect the
// PSC Warehouse (sign in) connector in Claude. Every access decision is made by
// Supabase Auth and the connector, not by this page.
(async () => {
  const SUPABASE_URL = 'https://qsunjpebauxprqjlkloz.supabase.co'
  const PUBLISHABLE_KEY = 'sb_publishable_rndoKdCgxv6x5PCNSRHyOg_38QxcOjF'
  const ALLOWED_HOSTS = ['claude.ai', 'claude.com']

  // The sign-in lives in this tab only (sessionStorage) and is cleared on the way back to Claude.
  const sb = supabase.createClient(SUPABASE_URL, PUBLISHABLE_KEY, {
    auth: { flowType: 'pkce', detectSessionInUrl: true, persistSession: true, storage: window.sessionStorage },
  })

  const $ = (id) => document.getElementById(id)
  const show = (id) => { for (const x of ['loading', 'signin', 'consent']) $(x).classList.toggle('hidden', x !== id) }
  const fail = (msg) => { $('error').textContent = msg; $('error').classList.remove('hidden'); $('loading').classList.add('hidden') }

  const params = new URLSearchParams(location.search)
  const authId = params.get('authorization_id')
  if (!authId) return fail('This page is opened by Claude when you connect the PSC Warehouse connector. Start from Claude.')
  const here = location.origin + location.pathname + '?authorization_id=' + encodeURIComponent(authId)

  const hostAllowed = (u) => {
    try { const h = new URL(u).hostname; return ALLOWED_HOSTS.some((a) => h === a || h.endsWith('.' + a)) } catch { return false }
  }
  const leave = (u) => {
    if (!hostAllowed(u)) return fail('Blocked: this request does not return to Claude.')
    try { window.sessionStorage.clear() } catch { /* ignore */ }
    location.href = u
  }

  $('google').onclick = async () => {
    const { error } = await sb.auth.signInWithOAuth({ provider: 'google', options: { redirectTo: here } })
    if (error) fail(error.message)
  }
  $('show-pw').onclick = () => { $('pw').classList.remove('hidden'); $('show-pw').classList.add('hidden') }
  $('pw').onsubmit = async (e) => {
    e.preventDefault()
    const { error } = await sb.auth.signInWithPassword({ email: $('email').value.trim(), password: $('password').value })
    if (error) return fail(error.message)
    location.replace(here)
  }
  $('signout').onclick = async () => { await sb.auth.signOut({ scope: 'local' }); location.replace(here) }

  const { data: { session } } = await sb.auth.getSession()
  if (params.get('code') && session) return location.replace(here)
  if (!session) return show('signin')

  const { data: details, error } = await sb.auth.oauth.getAuthorizationDetails(authId)
  if (error) return fail(error.message)
  if (!('authorization_id' in details)) return leave(details.redirect_url)
  if (!hostAllowed(details.redirect_uri)) return fail('Blocked: this request does not return to Claude.')

  $('who').textContent = session.user.email
  show('consent')
  $('approve').onclick = async () => {
    const { data, error } = await sb.auth.oauth.approveAuthorization(authId)
    if (error) return fail(error.message)
    leave(data.redirect_url)
  }
  $('deny').onclick = async () => {
    const { data, error } = await sb.auth.oauth.denyAuthorization(authId)
    if (error) return fail(error.message)
    leave(data.redirect_url)
  }
})().catch((e) => {
  const el = document.getElementById('error')
  el.textContent = String((e && e.message) || e)
  el.classList.remove('hidden')
})
