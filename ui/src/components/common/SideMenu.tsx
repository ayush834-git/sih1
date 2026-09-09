import React from 'react';
import './SideMenu.css';

export interface SideMenuProps {
  className?: string;
}

export const SideMenu: React.FC<SideMenuProps> = ({ className = '' }) => {
  return (
    <div className={`sm-13 ${className}`}>
      <input type="checkbox" id="sm-13-chk" />
      <label className="sm-13__burger" htmlFor="sm-13-chk" aria-label="Toggle menu">
        <span></span>
        <span></span>
        <span></span>
      </label>

      {/* Clicking overlay also closes the menu */}
      <label className="sm-13__overlay" htmlFor="sm-13-chk"></label>

      <nav className="sm-13__nav">
        <div className="sm-13__links">
          <a className="sm-13__link sm-13__link--active" href="/pipeline/observe">
            <span className="sm-13__link-chip"></span> Dashboard
          </a>
          <a className="sm-13__link" href="/pipeline/predict">
            <span className="sm-13__link-chip"></span> Analytics
          </a>
          <a className="sm-13__link" href="/pipeline/simulate">
            <span className="sm-13__link-chip"></span> Content
          </a>
          <a className="sm-13__link" href="/pipeline/approve">
            <span className="sm-13__link-chip"></span> Audience
          </a>
          <div className="sm-13__divider"></div>
          <a className="sm-13__link" href="/pipeline/verify">
            <span className="sm-13__link-chip"></span> Help
          </a>
          <a className="sm-13__link" href="/pipeline/trace">
            <span className="sm-13__link-chip"></span> Settings
          </a>
        </div>

        <div className="sm-13__user">
          <div className="sm-13__avatar">CK</div>
          <div>
            <div className="sm-13__uname">C. Kim</div>
            <div className="sm-13__urole">Publisher</div>
          </div>
        </div>
      </nav>

      <div className="sm-13__content">
        <div className="sm-13__heading">Checkbox Hack Menu</div>
        <div className="sm-13__sub">
          Uses a hidden <code>&lt;input type="checkbox"&gt;</code> and the CSS sibling combinator. No JavaScript at all.
        </div>
        <div className="sm-13__code-card">
          <span className="sel">#chk:checked ~ .nav</span> {'{\n'}
          &nbsp;&nbsp;<span className="kw">transform</span>: translateX(0);{'\n'}
          {'}\n'}
          <span className="sel">#chk:checked ~ .burger span:nth-child(1)</span> {'{\n'}
          &nbsp;&nbsp;<span className="kw">transform</span>: translateY(8px) rotate(45deg);{'\n'}
          {'}'}
        </div>
        <div className="sm-13__grid">
          <div className="sm-13__card">
            <div className="sm-13__card-val">0 JS</div>
            <div className="sm-13__card-lbl">Lines of JS</div>
          </div>
          <div className="sm-13__card">
            <div className="sm-13__card-val">100%</div>
            <div className="sm-13__card-lbl">Pure CSS</div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default SideMenu;
