import { createFileRoute, useNavigate, Link } from '@tanstack/react-router';
import { useState } from 'react';
import { ArrowRight, Smartphone, CheckCircle2 } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { useStore } from '@/lib/store';
import { pageHead } from '@/lib/metadata';
import type { User } from '@/lib/catalog';
export const Route = createFileRoute('/login')({ head: () => pageHead('Log in', 'Sign in to your QuickKart account with a phone number and one-time code.'), component: Login });
function Login() {
 const { user, request, login, ready } = useStore(); const navigate = useNavigate();
 const [phone, setPhone] = useState(''); const [otp, setOtp] = useState(''); const [sent, setSent] = useState(false); const [code, setCode] = useState(''); const [busy, setBusy] = useState(false); const [error, setError] = useState('');
 async function submit(e: React.FormEvent) { e.preventDefault(); setBusy(true); setError(''); try { if (!sent) { const data = await request<{ otp: string }>('/auth/send-otp', { phone }); setCode(data.otp); setSent(true); } else { const data = await request<{ user: User; token: string }>('/auth/verify-otp', { phone, otp }); login(data.user, data.token); await navigate({ to: '/' }); } } catch(e) { setError(e instanceof Error ? e.message : 'Try again'); } finally { setBusy(false); } }
 return <main className="account-main">{user ? <div className="account-form"><CheckCircle2 /><h1>You’re signed in</h1><Button asChild><Link to="/profile">My profile</Link></Button></div> : <form className="account-form" onSubmit={submit}><div className="form-symbol"><Smartphone /></div><span className="eyebrow">YOUR CAMPUS, YOUR CART</span><h1>Welcome to QuickKart.</h1><p>Sign in with your mobile number.</p><label>Mobile number<div className="phone-input"><span>+91</span><input aria-label="Mobile number" type="tel" pattern="[0-9]{10}" maxLength={10} placeholder="9000000001" required disabled={sent} value={phone} onChange={e => setPhone(e.target.value)} /></div></label>{sent && <><label>One-time code<input aria-label="One-time code" inputMode="numeric" pattern="[0-9]{6}" maxLength={6} required value={otp} onChange={e => setOtp(e.target.value)} /></label><div className="code-message">Your one-time code: <strong>{code}</strong></div></>}{error && <p role="alert" className="error-text">{error}</p>}<Button disabled={busy || !ready} type="submit" size="lg">{busy ? 'Please wait...' : sent ? 'Verify & log in' : 'Get one-time code'}<ArrowRight /></Button>{sent && <Button type="button" variant="link" onClick={() => { setSent(false); setOtp(''); }}>Use another number</Button>}<span className="form-caption">Sample accounts: 9000000001–9000000005</span></form>}</main>;
}
