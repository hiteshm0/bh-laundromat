import { createFileRoute, Link } from '@tanstack/react-router';
import { useState, useEffect } from 'react';
import { Save, UserRound } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { useStore } from '@/lib/store';
import { pageHead } from '@/lib/metadata';
import type { User } from '@/lib/catalog';
export const Route = createFileRoute('/profile')({ head: () => pageHead('My profile', 'Manage your QuickKart name, phone, delivery address and PAN details.'), component: Profile });
function Profile() { const { user, request, saveUser } = useStore(); const [name, setName] = useState(''); const [address, setAddress] = useState(''); const [pan, setPan] = useState(''); const [message, setMessage] = useState(''); const [busy, setBusy] = useState(false); useEffect(() => { setName(user?.name ?? ''); setAddress(user?.address ?? ''); setPan(user?.pan ?? ''); }, [user]);
 async function save(e: React.FormEvent) { e.preventDefault(); setBusy(true); try { saveUser(await request<User>('/profile', { name, address, pan })); setMessage('Profile saved'); } catch(e) { setMessage(e instanceof Error ? e.message : 'Try again'); } finally { setBusy(false); } }
 return <main className="page-main"><span className="eyebrow">MY ACCOUNT</span><h1>My profile</h1>{!user ? <div className="empty-state"><UserRound /><h2>A place for your details.</h2><Button asChild><Link to="/login">Log in</Link></Button></div> : <form className="profile-form" onSubmit={save}><label>Full name<input required maxLength={100} value={name} onChange={e => setName(e.target.value)} /></label><label>Mobile number<input disabled value={user.phone} /></label><label>Delivery address<textarea required maxLength={500} value={address} onChange={e => setAddress(e.target.value)} /></label><label>PAN number<input maxLength={20} value={pan} onChange={e => setPan(e.target.value)} /></label><Button type="submit" disabled={busy}><Save />{busy ? 'Saving...' : 'Save profile'}</Button>{message && <p role="status">{message}</p>}</form>}</main>; }
