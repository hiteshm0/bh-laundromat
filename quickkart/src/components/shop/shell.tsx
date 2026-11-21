import { Link, useRouterState } from '@tanstack/react-router';
import { ShoppingBag, Package, UserRound, ArrowUpRight, ShieldCheck, Truck, LogOut } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { useStore } from '@/lib/store';
import { storeConfig } from '@/lib/store-config';

export function ShopHeader() {
  const { user, basket, logout } = useStore();
  const path = useRouterState({ select: s => s.location.pathname });
  const count = basket.reduce((sum, item) => sum + item.quantity, 0);
  return <><div className="announcement"><span>Campus essentials. Student-friendly prices.</span><span>Made for your everyday <ArrowUpRight size={12} /></span></div><header className="shop-header"><Link to="/" className="wordmark"><ShoppingBag strokeWidth={2.5} /><span>QuickKart<span className="brand-dot">.</span></span></Link><nav aria-label="Main navigation"><Link to="/" className={path === '/' ? 'nav-active' : ''}>Shop</Link><Link to="/orders" className={path === '/orders' ? 'nav-active' : ''}><Package size={16} />My orders</Link></nav><div className="header-actions"><Button variant="ghost" asChild><Link to={user ? '/profile' : '/login'}><UserRound /> <span>{user ? user.name.split(' ')[0] : 'Log in'}</span></Link></Button>{user && <Button variant="ghost" size="icon" title="Log out" aria-label="Log out" onClick={logout}><LogOut /></Button>}<Button variant="outline" asChild><Link to="/checkout"><ShoppingBag /><span className="cart-label">Cart</span><span className="cart-count">{count}</span></Link></Button></div></header></>;
}
export function ShopFooter() {
  return <footer className="shop-footer"><div className="footer-main"><Link to="/" className="wordmark">QuickKart<span className="brand-dot">.</span></Link><span>A little more campus. A little less spend.</span><div><Link to="/orders">Orders</Link><Link to="/profile">My account</Link><Link to="/admin">Admin</Link></div></div><div className="footer-bottom"><span>© 2026 QuickKart</span><span>All prices in {storeConfig.currency} · Made for student life</span></div></footer>;
}
export function TrustStrip() { return <div className="trust-strip"><span><Truck /> Free delivery on every order</span><span><ShieldCheck /> Easy 7-day returns</span><span><ShoppingBag /> Handpicked for campus life</span></div>; }
