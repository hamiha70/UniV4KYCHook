import React, { useEffect, useState } from 'react';
import { useContractRead, useContractWrite, useWaitForTransaction } from 'wagmi';
import { ethers } from 'ethers';

const contracts = [
  {
    address: '0xYourContractAddress1',
    abi: [/* ABI for contract 1 */],
    functionName: 'yourFunctionName1',
  },
  {
    address: '0xYourContractAddress2',
    abi: [/* ABI for contract 2 */],
    functionName: 'yourFunctionName2',
  },
  // Add more contracts as needed
];

function ContractInteraction() {
  const [results, setResults] = useState([]);
  const [isLoading, setIsLoading] = useState(true);

  useEffect(() => {
    const fetchData = async () => {
      const data = await Promise.all(
        contracts.map(async (contract) => {
          const { data } = await useContractRead({
            addressOrName: contract.address,
            contractInterface: contract.abi,
            functionName: contract.functionName,
          });
          return data;
        })
      );
      setResults(data);
      setIsLoading(false);
    };

    fetchData();
  }, []);

  return (
    <div>
      {isLoading ? (
        <p>Loading...</p>
      ) : (
        results.map((result, index) => (
          <div key={index}>
            <p>Contract {index + 1} Result: {result}</p>
          </div>
        ))
      )}
    </div>
  );
}

export default ContractInteraction;
