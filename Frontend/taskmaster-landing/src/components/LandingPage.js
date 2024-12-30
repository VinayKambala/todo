import React from 'react';
import Navbar from './Navbar.js';        // Assuming Navbar component is in the same directory
import HeroSection from './HeroSection.js'; // Assuming HeroSection component is in the same directory
import FeaturesSection from './FeaturesSection.js'; // Assuming FeaturesSection component is in the same directory
import PricingSection from './PricingSection.js';   // Assuming PricingSection component is in the same directory
import Footer from './Footer.js';
const Landing = () => {
  return (
    <div>
      <Navbar />
      <HeroSection />
      <FeaturesSection />
      <PricingSection />
      <Footer />

    </div>
  );
};

export default Landing;
