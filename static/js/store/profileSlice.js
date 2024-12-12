import { createSlice } from '@reduxjs/toolkit';

const initialState = {
  currentModal: null,
  currentUserId: null,
  userData: null,
  loading: false,
  error: null
};

export const profileSlice = createSlice({
  name: 'profile',
  initialState,
  reducers: {
    setCurrentModal: (state, action) => {
      state.currentModal = action.payload;
    },
    setCurrentUserId: (state, action) => {
      state.currentUserId = action.payload;
    },
    setUserData: (state, action) => {
      state.userData = action.payload;
    },
    setLoading: (state, action) => {
      state.loading = action.payload;
    },
    setError: (state, action) => {
      state.error = action.payload;
    },
    clearProfile: (state) => {
      state.currentModal = null;
      state.currentUserId = null;
      state.userData = null;
      state.error = null;
    }
  }
});

export const { 
  setCurrentModal, 
  setCurrentUserId, 
  setUserData, 
  setLoading, 
  setError, 
  clearProfile 
} = profileSlice.actions;

export default profileSlice.reducer;
