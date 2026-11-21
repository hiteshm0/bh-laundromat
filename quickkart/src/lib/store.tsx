import { createContext, useContext, useEffect, useState, type ReactNode } from 'react';
import { products, users, seededOrders, type User, type Order, type Product } from './catalog';
import { localRequest } from './local-api';

type BasketItem = { productId: number; quantity: number };
type Store = {
  user: User | null; local: boolean; ready: boolean; basket: BasketItem[]; orders: Order[];
  add: (id: number) => void; change: (id: number, amount: number) => void;
  request: <T>(path: string, body?: unknown) => Promise<T>;
  login: (user: User, token: string) => void; logout: () => void;
  saveUser: (user: User) => void; complete: (order: Order) => void;
};
const StoreContext = createContext<Store | null>(null);
export function StoreProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<User | null>(null);
  const [token, setToken] = useState<string | null>(null);
  const [local, setLocal] = useState(false);
  const [ready, setReady] = useState(false);
  const [basket, setBasket] = useState<BasketItem[]>([]);
  const [orders, setOrders] = useState<Order[]>(seededOrders);
  const [otp, setOtp] = useState('');
  useEffect(() => {
    if (!['localhost', '127.0.0.1'].includes(window.location.hostname)) { setReady(true); return; }
    localRequest('/health', null).then(async () => {
      setLocal(true);
      const saved = sessionStorage.getItem('quickkart-session');
      if (saved) {
        try { setUser(await localRequest<User>('/me', saved)); setToken(saved); }
        catch { sessionStorage.removeItem('quickkart-session'); }
      }
    }).catch(() => {}).finally(() => setReady(true));
  }, []);
  async function request<T>(path: string, body?: unknown): Promise<T> {
    if (local) return localRequest<T>(path, token, body);
    const data = body as Record<string, unknown> | undefined;
    let result: unknown;
    if (path.startsWith('/search')) result = products.filter(p => p.name.toLowerCase().includes((new URLSearchParams(path.split('?')[1]).get('q') ?? '').toLowerCase()));
    else if (path === '/auth/send-otp') { setOtp('123456'); result = { otp: '123456', expiresIn: 300 }; }
    else if (path === '/auth/verify-otp') {
      if (data?.['otp'] !== otp || !otp) throw new Error('Incorrect OTP');
      const found = users.find(u => u.phone === data?.['phone']);
      if (!found) throw new Error('Use a sample phone from 9000000001 to 9000000005');
      setOtp(''); result = { user: found, token: 'FAKE_PREVIEW_SESSION' };
    }
    else if (path === '/admin/users') result = users;
    else if (path === '/admin/orders') { if (user?.role !== 'admin') throw new Error('Admin access required'); result = orders; }
    else if (path === '/orders') { if (!user) throw new Error('Please sign in'); result = orders.filter(o => o.user_id === user.id); }
    else if (path.startsWith('/orders/')) { if (!user) throw new Error('Please sign in'); result = orders.find(o => o.id === Number(path.split('/').at(-1))); if (!result) throw new Error('Order not found'); }
    else if (path === '/profile') { if (!user) throw new Error('Please sign in'); result = { ...user, ...data }; }
    else if (path === '/checkout') {
      if (!user) throw new Error('Please sign in');
      const items = (data?.['items'] as BasketItem[]).flatMap(item => { const p = products.find(p => p.id === item.productId); return p ? [{ ...p, quantity: item.quantity }] : []; });
      result = { id: Math.max(...orders.map(o => o.id)) + 1, user_id: user.id, total: items.reduce((sum, p) => sum + p.price * p.quantity, 0), status: data?.['paymentSuccess'] === true ? 'Paid' : 'Pending payment', created_at: new Date().toISOString(), items };
    } else throw new Error('Request unavailable');
    return result as T;
  }
  function change(id: number, amount: number) { setBasket(current => current.map(item => item.productId === id ? { ...item, quantity: Math.min(20, item.quantity + amount) } : item).filter(item => item.quantity > 0)); }
  return <StoreContext.Provider value={{ user, local, ready, basket, orders, request, add: id => setBasket(current => current.some(item => item.productId === id) ? current.map(item => item.productId === id ? { ...item, quantity: Math.min(20, item.quantity + 1) } : item) : [...current, { productId: id, quantity: 1 }]), change, login: (u, t) => { setUser(u); setToken(t); if (local) sessionStorage.setItem('quickkart-session', t); }, logout: () => { setUser(null); setToken(null); setBasket([]); sessionStorage.removeItem('quickkart-session'); }, saveUser: setUser, complete: order => { setOrders(current => [order, ...current]); setBasket([]); } }}>{children}</StoreContext.Provider>;
}
export function useStore() { const store = useContext(StoreContext); if (!store) throw new Error('Store unavailable'); return store; }
export function basketProducts(basket: BasketItem[]): (Product & { quantity: number })[] { return basket.flatMap(item => { const p = products.find(p => p.id === item.productId); return p ? [{ ...p, quantity: item.quantity }] : []; }); }
