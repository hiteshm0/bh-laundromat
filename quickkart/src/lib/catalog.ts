import backpack from '@/assets/backpack.jpg.asset.json';
import headphones from '@/assets/headphones.jpg.asset.json';
import notebooks from '@/assets/notebooks.jpg.asset.json';
import lamp from '@/assets/lamp.jpg.asset.json';
import bottle from '@/assets/bottle.jpg.asset.json';
import keyboard from '@/assets/keyboard.jpg.asset.json';

export type Product = { id: number; name: string; category: string; price: number; original_price: number; rating: number; image: string };
export type User = { id: number; name: string; phone: string; address: string; pan: string; role: string };
export type Order = { id: number; user_id: number; total: number; status: string; created_at: string; items?: (Product & { quantity: number })[] };
export const photos: Record<string, string> = { backpack: backpack.url, headphones: headphones.url, notebooks: notebooks.url, lamp: lamp.url, bottle: bottle.url, keyboard: keyboard.url };
export const products: Product[] = [
  { id: 1, name: 'Everyday Campus Backpack', category: 'Bags & Accessories', price: 899, original_price: 1299, rating: 4.8, image: 'backpack' },
  { id: 2, name: 'Tune In Wireless Headphones', category: 'Electronics', price: 1499, original_price: 2499, rating: 4.7, image: 'headphones' },
  { id: 3, name: 'The Study Club Notebook Set', category: 'Stationery', price: 249, original_price: 399, rating: 4.9, image: 'notebooks' },
  { id: 4, name: 'Late Night Study Lamp', category: 'Room Essentials', price: 699, original_price: 999, rating: 4.6, image: 'lamp' },
  { id: 5, name: 'Everyday Steel Bottle · 750ml', category: 'Bags & Accessories', price: 449, original_price: 699, rating: 4.8, image: 'bottle' },
  { id: 6, name: 'Type Club Mechanical Keyboard', category: 'Electronics', price: 1899, original_price: 2999, rating: 4.7, image: 'keyboard' },
];
export const users: User[] = ['Aarav Sharma', 'Diya Patel', 'Kabir Rao', 'Meera Iyer', 'Rohan Das'].map((name, index) => ({ id: index + 1, name, phone: `900000000${index + 1}`, address: `Room ${(index + 1) * 12}, Sample College Hostel`, pan: `FAKEPAN00${index + 1}`, role: index === 4 ? 'admin' : 'student' }));
export const seededOrders: Order[] = users.map((user, i) => {
  const product = products[i];
  return { id: 1001 + i, user_id: user.id, total: product?.price ?? 0, status: i === 1 ? 'Shipped' : 'Delivered', created_at: '2026-11-14', items: product ? [{ ...product, quantity: 1 }] : [] };
});
export const rupees = (value: number) => `₹${value.toLocaleString('en-IN')}`;
export const categories = ['All products', 'Electronics', 'Stationery', 'Bags & Accessories', 'Room Essentials'];
