package com.lauriewired;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.util.task.TaskMonitor;

import java.security.InvalidParameterException;
import java.util.ArrayList;
import java.util.List;

final class SignatureUtils {

    static class SignatureGenerationException extends Exception {
        SignatureGenerationException(String message) {
            super(message);
        }
    }

    private static final class ByteSignature {
        private final byte[] bytes;
        private final byte[] mask;

        ByteSignature(String signature) {
            List<String> tokens = tokenizeSignature(signature);
            bytes = new byte[tokens.size()];
            mask = new byte[tokens.size()];

            for (int index = 0; index < tokens.size(); index++) {
                String token = tokens.get(index);
                if (isWildcardToken(token)) {
                    bytes[index] = 0;
                    mask[index] = 0;
                    continue;
                }

                bytes[index] = (byte) Integer.parseInt(token, 16);
                mask[index] = 1;
            }
        }

        byte[] getBytes() {
            return bytes;
        }

        byte[] getMask() {
            return mask;
        }
    }

    private SignatureUtils() {
    }

    static String createUniqueSignature(Program program, Function function, TaskMonitor monitor)
            throws SignatureGenerationException, MemoryAccessException {
        if (program == null) {
            throw new SignatureGenerationException("No program loaded");
        }
        if (function == null) {
            throw new SignatureGenerationException("No function selected");
        }

        InstructionIterator instructions = program.getListing().getInstructions(function.getBody(), true);
        if (!instructions.hasNext()) {
            throw new SignatureGenerationException("Function has no instructions");
        }

        String signature = buildSignatureFromInstructions(instructions);
        Address functionAddress = function.getBody().getMinAddress();
        Address foundAddress = findAddressForSignature(program, signature, monitor);

        if (foundAddress == null || !foundAddress.equals(functionAddress)) {
            throw new SignatureGenerationException(
                "Function is not large enough to create a unique signature"
            );
        }

        return refineSignature(program, signature, functionAddress, monitor);
    }

    static Address findAddressForSignature(Program program, String signature, TaskMonitor monitor) {
        if (program == null) {
            throw new InvalidParameterException("No program loaded");
        }

        ByteSignature byteSignature = new ByteSignature(signature);
        return program.getMemory().findBytes(
            program.getMinAddress(),
            program.getMaxAddress(),
            byteSignature.getBytes(),
            byteSignature.getMask(),
            true,
            monitor
        );
    }

    private static String buildSignatureFromInstructions(InstructionIterator instructions)
            throws MemoryAccessException {
        List<String> tokens = new ArrayList<>();

        for (Instruction instruction : instructions) {
            byte[] bytes = instruction.getBytes();
            if (instruction.isFallthrough()) {
                for (byte value : bytes) {
                    tokens.add(String.format("%02X", value));
                }
                continue;
            }

            for (int index = 0; index < bytes.length; index++) {
                tokens.add("?");
            }
        }

        return joinTokens(tokens);
    }

    private static String refineSignature(Program program, String signature, Address functionAddress, TaskMonitor monitor) {
        List<String> currentTokens = trimTrailingWildcards(tokenizeSignature(signature));
        if (currentTokens.isEmpty()) {
            return "";
        }

        while (currentTokens.size() > 1) {
            List<String> candidateTokens = trimTrailingWildcards(
                new ArrayList<>(currentTokens.subList(0, currentTokens.size() - 1))
            );
            if (candidateTokens.isEmpty()) {
                break;
            }

            Address foundAddress = findAddressForSignature(program, joinTokens(candidateTokens), monitor);
            if (foundAddress == null || !foundAddress.equals(functionAddress)) {
                break;
            }

            currentTokens = candidateTokens;
        }

        return joinTokens(currentTokens);
    }

    private static List<String> tokenizeSignature(String signature) {
        if (signature == null) {
            throw new InvalidParameterException("Signature cannot be empty");
        }

        String normalized = signature.trim();
        if (normalized.isEmpty()) {
            throw new InvalidParameterException("Signature cannot be empty");
        }

        String[] rawTokens = normalized.split("\\s+");
        List<String> tokens = new ArrayList<>(rawTokens.length);
        for (String rawToken : rawTokens) {
            if (rawToken.isEmpty()) {
                continue;
            }
            if (isWildcardToken(rawToken)) {
                tokens.add("?");
                continue;
            }
            if (rawToken.length() != 2) {
                throw new InvalidParameterException("Invalid byte token: " + rawToken);
            }

            try {
                Integer.parseInt(rawToken, 16);
                tokens.add(rawToken.toUpperCase());
            } catch (NumberFormatException exception) {
                throw new InvalidParameterException("Invalid byte token: " + rawToken);
            }
        }

        if (tokens.isEmpty()) {
            throw new InvalidParameterException("Signature cannot be empty");
        }

        return tokens;
    }

    private static List<String> trimTrailingWildcards(List<String> tokens) {
        int end = tokens.size();
        while (end > 0 && isWildcardToken(tokens.get(end - 1))) {
            end--;
        }
        return new ArrayList<>(tokens.subList(0, end));
    }

    private static boolean isWildcardToken(String token) {
        if (token == null || token.isEmpty()) {
            return false;
        }
        for (int index = 0; index < token.length(); index++) {
            if (token.charAt(index) != '?') {
                return false;
            }
        }
        return true;
    }

    private static String joinTokens(List<String> tokens) {
        return String.join(" ", tokens);
    }
}