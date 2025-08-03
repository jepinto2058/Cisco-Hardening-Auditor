
import { escapeHtml } from '../utils/escape.js';
import { Severity } from '../constants.js';

// --- ICONS ---
export const UploadCloudIcon = (props = {}) => {
  const classNames = props.className || "w-10 h-10";
  return `<svg class="${escapeHtml(classNames)}" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke-width="1.5" stroke="currentColor">
    <title>Upload Cloud</title>
    <path stroke-linecap="round" stroke-linejoin="round" d="M12 16.5V9.75m0 0l3 3m-3-3l-3 3M6.75 19.5a4.5 4.5 0 01-1.41-8.775 5.25 5.25 0 0110.338-2.32 5.75 5.75 0 011.344 11.096h-1.344M19.5 19.5a4.5 4.5 0 00-4.5-4.5" />
  </svg>`;
};
export const ChevronDownIcon = (props = {}) => `<svg class="${escapeHtml(props.className || 'w-5 h-5')}" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke-width="1.5" stroke="currentColor"><title>Chevron Down</title><path stroke-linecap="round" stroke-linejoin="round" d="M19.5 8.25l-7.5 7.5-7.5-7.5" /></svg>`;
export const ChevronUpIcon = (props = {}) => `<svg class="${escapeHtml(props.className || 'w-5 h-5')}" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke-width="1.5" stroke="currentColor"><title>Chevron Up</title><path stroke-linecap="round" stroke-linejoin="round" d="M4.5 15.75l7.5-7.5 7.5 7.5" /></svg>`;
export const InfoIcon = (props = {}) => `<svg class="${escapeHtml(props.className || 'w-5 h-5')}" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke-width="1.5" stroke="currentColor"><title>Info</title><path stroke-linecap="round" stroke-linejoin="round" d="M11.25 11.25l.041-.02a.75.75 0 011.063.852l-.708 2.836a.75.75 0 001.063.853l.041-.021M21 12a9 9 0 11-18 0 9 9 0 0118 0zm-9-3.75h.008v.008H12V8.25z" /></svg>`;
export const WarningIcon = (props = {}) => `<svg class="${escapeHtml(props.className || 'w-5 h-5')}" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke-width="1.5" stroke="currentColor"><title>Warning</title><path stroke-linecap="round" stroke-linejoin="round" d="M12 9v3.75m-9.303 3.376c-.866 1.5.217 3.374 1.948 3.374h14.71c1.73 0 2.813-1.874 1.948-3.374L13.949 3.378c-.866-1.5-3.032-1.5-3.898 0L2.697 16.126zM12 15.75h.007v.008H12v-.008z" /></svg>`;
export const ErrorIconSvg = (props = {}) => `<svg class="${escapeHtml(props.className || 'w-5 h-5')}" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="currentColor"><title>Error</title><path fill-rule="evenodd" d="M9.401 3.003c1.155-2 4.043-2 5.197 0l7.316 12.672c1.155 2-.772 4.5-3.099 4.5H5.183c-2.326 0-4.253-2.5-3.1-4.5L9.4 3.003zM12 8.25a.75.75 0 01.75.75v3.75a.75.75 0 01-1.5 0V9a.75.75 0 01.75-.75zm0 8.25a.75.75 0 100-1.5.75.75 0 000 1.5z" clip-rule="evenodd" /></svg>`;
export const CheckCircleIcon = (props = {}) => `<svg class="${escapeHtml(props.className || 'w-5 h-5')}" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke-width="1.5" stroke="currentColor"><title>Check Circle</title><path stroke-linecap="round" stroke-linejoin="round" d="M9 12.75L11.25 15 15 9.75M21 12a9 9 0 11-18 0 9 9 0 0118 0z" /></svg>`;
export const ShieldExclamationIcon = (props = {}) => `<svg class="${escapeHtml(props.className || 'w-5 h-5')}" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke-width="1.5" stroke="currentColor"><title>Shield Exclamation</title><path stroke-linecap="round" stroke-linejoin="round" d="M12 9v3.75m0-10.036A11.959 11.959 0 013.598 6 11.99 11.99 0 003 9.75c0 5.592 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.31-.21-2.57-.598-3.75h-.152c-3.196 0-6.1-1.24-8.25-3.286zm0 12.984a2.25 2.25 0 100-4.5 2.25 2.25 0 000 4.5z" /></svg>`;
export const FileHtmlIcon = (props = {}) => `<svg class="${escapeHtml(props.className || 'w-5 h-5')}" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke-width="1.5" stroke="currentColor"><title>HTML File</title><path stroke-linecap="round" stroke-linejoin="round" d="M9.75 3.104v5.625a2.25 2.25 0 01-2.25 2.25H3.375V18a2.25 2.25 0 002.25 2.25h12.75A2.25 2.25 0 0020.625 18V6.375a2.25 2.25 0 00-2.25-2.25H9.75z" /><path stroke-linecap="round" stroke-linejoin="round" d="M14.25 3.104V7.5A2.25 2.25 0 0012 9.75H7.5V3.104m0 0L3.375 7.5M14.25 3.104L18.375 7.5" /><path stroke-linecap="round" stroke-linejoin="round" d="M10.5 13.5l-1.5 1.5 1.5 1.5m3-3l1.5 1.5-1.5 1.5" /></svg>`;
export const FilePdfIcon = (props = {}) => `<svg class="${escapeHtml(props.className || 'w-5 h-5')}" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke-width="1.5" stroke="currentColor"><title>PDF File</title><path stroke-linecap="round" stroke-linejoin="round" d="M9.75 3.104V7.5A2.25 2.25 0 017.5 9.75H3.375V18a2.25 2.25 0 002.25 2.25h12.75A2.25 2.25 0 0020.625 18V6.375a2.25 2.25 0 00-2.25-2.25H9.75z" /><path stroke-linecap="round" stroke-linejoin="round" d="M15.75 6.75h.008v.008h-.008V6.75zm.75 6.75h.008v.008h-.008v-.008zm-.75 2.25h.008v.008h-.008v-.008zM9.75 13.5h3.75M9.75 15.75h3.75M7.5 18v-3.75" /><path stroke-linecap="round" stroke-linejoin="round" d="M14.25 3.104V7.5A2.25 2.25 0 0012 9.75H7.5V3.104m0 0L3.375 7.5M14.25 3.104L18.375 7.5" /></svg>`;
export const ChartBarIcon = (props = {}) => `<svg class="${escapeHtml(props.className || 'w-5 h-5')}" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke-width="1.5" stroke="currentColor"><title>Summary Chart</title><path stroke-linecap="round" stroke-linejoin="round" d="M3 13.125C3 12.504 3.504 12 4.125 12h2.25c.621 0 1.125.504 1.125 1.125v6.75C7.5 20.496 6.996 21 6.375 21h-2.25A1.125 1.125 0 013 19.875v-6.75zM9.75 8.625c0-.621.504-1.125 1.125-1.125h2.25c.621 0 1.125.504 1.125 1.125v11.25c0 .621-.504 1.125-1.125 1.125h-2.25a1.125 1.125 0 01-1.125-1.125V8.625zM16.5 4.125c0-.621.504-1.125 1.125-1.125h2.25C20.496 3 21 3.504 21 4.125v15.75c0 .621-.504 1.125-1.125 1.125h-2.25a1.125 1.125 0 01-1.125-1.125V4.125z" /></svg>`;
export const MagnifyingGlassIcon = (props = {}) => `<svg class="${escapeHtml(props.className || 'w-5 h-5')}" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke-width="1.5" stroke="currentColor"><title>View Details</title><path stroke-linecap="round" stroke-linejoin="round" d="M21 21l-5.197-5.197m0 0A7.5 7.5 0 105.196 5.196a7.5 7.5 0 0010.607 10.607z" /></svg>`;


// --- COMPOSITE ICON FUNCTIONS ---
export const jsSeverityIcon = (severity, className = "w-5 h-5") => {
  switch (severity) {
    case Severity.CRITICAL:
      return ErrorIconSvg({ className: `${className} text-red-500` });
    case Severity.HIGH:
      return ShieldExclamationIcon({ className: `${className} text-orange-500` });
    case Severity.MEDIUM:
      return WarningIcon({ className: `${className} text-yellow-500` });
    case Severity.LOW:
      return InfoIcon({ className: `${className} text-blue-500` });
    case Severity.INFORMATIONAL:
      return InfoIcon({ className: `${className} text-gray-500` });
    default:
      return '';
  }
};

// --- GENERAL COMPONENTS ---
export const createButtonHTML = (id, text, variant = 'primary', additionalClasses = '', disabled = false, iconHTML = '') => {
  const baseStyle = "px-4 py-2 sm:px-6 sm:py-3 rounded-md font-semibold focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-offset-slate-900 transition-colors duration-150 disabled:opacity-60 disabled:cursor-not-allowed flex items-center justify-center space-x-2";
  let variantStyle = '';
  switch (variant) {
    case 'primary': variantStyle = 'bg-sky-600 text-white hover:bg-sky-500 focus:ring-sky-500'; break;
    case 'secondary': variantStyle = 'bg-slate-600 text-slate-100 hover:bg-slate-500 focus:ring-slate-500'; break;
    case 'danger': variantStyle = 'bg-red-600 text-white hover:bg-red-500 focus:ring-red-500'; break;
  }
  return `<button id="${escapeHtml(id)}" class="${baseStyle} ${variantStyle} ${escapeHtml(additionalClasses)}" ${disabled ? 'disabled' : ''}>${iconHTML}${iconHTML ? `<span>${escapeHtml(text)}</span>` : escapeHtml(text)}</button>`;
};

export const createCardHTML = (title, childrenHTML, cardClassName = '') => {
  return `
    <div class="bg-slate-800 shadow-xl rounded-lg ${escapeHtml(cardClassName)}">
      ${title ? `<div class="px-6 py-4 border-b border-slate-700"><h3 class="text-xl font-semibold text-sky-400">${escapeHtml(title)}</h3></div>` : ''}
      <div class="p-4 sm:p-6">
        ${childrenHTML}
      </div>
    </div>
  `;
};
