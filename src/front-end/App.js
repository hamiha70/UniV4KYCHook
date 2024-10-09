import React from 'react';
import { WagmiConfig } from 'wagmi';
import client from './wagmiClient';
import MultipleWallets from './MultipleWallets';
import ContractInteraction from './ContractInteraction';

function App() {
  return (
    <WagmiConfig client={client}>
      <div>
        <MultipleWallets />
        <ContractInteraction />
      </div>
    </WagmiConfig>
  );
}

export default App;
